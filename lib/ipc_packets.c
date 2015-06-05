/*
 * Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
 * All Rights Reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef IPC_PACKETS_TEST

#define VLOG_ERR        printf
#define VLOG_DBG(...)

#else // ! IPC_PACKETS_TEST

#include "poll.h"
#include "poll-loop.h"
#include "openvswitch/vlog.h"
VLOG_DEFINE_THIS_MODULE(ipc_packets);

#endif // ! IPC_PACKETS_TEST

#include "ipc_packets.h"

/******************************************************************************
*******************************************************************************
**
** EVERYTHING PRIVATE
**
** The following commands MUST be executed for the multicast to work
** properly, prior to running this library:
**
** root> ifconfig lo multicast
** root> route add -net <multicast_ip_address>  netmask 255.255.255.255 dev lo
**
*******************************************************************************
******************************************************************************/

#define UDP_BASE_PORT                   2060
#define MCAST_ADDRESS                   "224.0.0.200"
#define MAX_SOCKET_ENTRIES              (LAST_PKT - FIRST_PKT)

/*
** Socket entry which will be used
** to transmit & receive udp packets.
*/
typedef struct socket_entry_s {

    uint ipv4_addr;                             /* address bound to */
    uint ipv4_mcast_addr;                       /* member of multicast group */
    int fd;                                     /* file descriptor */
    packet_processing_function *ppfp;           /* user supplied function */

} socket_entry_t;

/*
** Each process has one of these.  The entries represent the
** list of sockets/fd open to *RECEIVE* packets of that specific
** type.  For transmitting packets out, any fd can be used.  So
** we cache any one of them (usually the latest one opened)
** for this purpose, into "transmit_fd".
*/
typedef struct sockets_table_s {

    int transmit_fd;
    socket_entry_t socket_entries_array [MAX_SOCKET_ENTRIES];

} sockets_table_t;

#define errno_string            (strerror(errno))

/*****************************************************************************/

/* forward declaration */
char *printable_pkt_type (packet_type_t pkt);

static inline int
invalid_pkt_type (packet_type_t pkt)
{
    return
        (((pkt) < FIRST_PKT) || ((pkt) >= LAST_PKT));
}

/*
** Given the packet type, returns
** the udp port that pkt should have been
** bound to.
*/
static inline int
pkt_type_to_udp_port (packet_type_t pkt)
{
    return
        (pkt - FIRST_PKT) + UDP_BASE_PORT;
}

static inline int
ipv4_addr_not_multicast (uint ipv4_mcast_addr)
{
    return
        ((ipv4_mcast_addr >> 28) != 14);
}

static char *
printable_ipv4_addr (uint ipv4_addr)
{
    static char buffer [20][20];
    static int bi = -1;

    /* cycle thru 20 buffers */
    bi++;
    if (bi >= 20) bi = 0;

    sprintf(&(buffer[bi][0]), "%u.%u.%u.%u",
        ((ipv4_addr >> 24) & 0xFF),
        ((ipv4_addr >> 16) & 0xFF),
        ((ipv4_addr >> 8) & 0xFF),
        ((ipv4_addr >> 0) & 0xFF)
    );

    return &(buffer[bi][0]);
}

static void
initialise_socket_entry_table (sockets_table_t *tablep)
{
    packet_type_t a;

    memset(tablep, 0, sizeof(sockets_table_t));
    tablep->transmit_fd = -1;
    for (a = FIRST_PKT; a < LAST_PKT; a++) {
        tablep->socket_entries_array[a].fd = -1;
    }
}

/*
** Creates a udp socket & returns the file descriptor.
** A return value of -1 indicates an error.
*/
static int
udp_socket_create (uint ipv4_addr, int udp_port_number)
{
    struct sockaddr_in sock;
    int fd;
    int option;

    /*
    ** open a fresh new socket
    */
    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) {
        VLOG_ERR("udp_socket_create: socket call failed "
            "for addr %s (%u) udp port %d: %s",
             printable_ipv4_addr(ipv4_addr), ipv4_addr,
             udp_port_number, errno_string);
        return -1;
    }

    /*
    ** Allow address to be reusable
    */
    option = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option))) {
        VLOG_ERR("udp_socket_create: setsockopt SO_REUSEADDR failed "
            "for fd %d addr %s (%u) udp port %d: %s",
            fd, printable_ipv4_addr(ipv4_addr), ipv4_addr,
            udp_port_number, errno_string);
        close(fd);
        return -1;
    }

    /*
    ** Bind addr & port
    */
    memset(&sock, 0, sizeof(sock));
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = htonl(ipv4_addr);
    sock.sin_port = htons(udp_port_number);
    if (bind(fd, (struct sockaddr*) &sock, sizeof(sock))) {
        VLOG_ERR("udp_socket_create: bind call failed "
            "for fd %d addr %s (%u) udp port %d: %s",
            fd, printable_ipv4_addr(ipv4_addr), ipv4_addr,
            udp_port_number, errno_string);
        close(fd);
        return -1;
    }

    /*
    ** I do NOT want to receive my own multicasts/broadcasts
    */
    option = 0;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &option, sizeof(option))) {
        VLOG_ERR("udp_socket_create: setsockopt IP_MULTICAST_LOOP call failed "
            "for fd %d addr %s (%u) udp port %d: %s",
            fd, printable_ipv4_addr(ipv4_addr), ipv4_addr,
            udp_port_number, errno_string);
        close(fd);
        return -1;
    }

    /*
    ** set all ttl's to 1
    */
    option = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &option, sizeof(option))) {
        VLOG_ERR("udp_socket_create: setsockopt IP_MULTICAST_TTL call failed "
            "for fd %d addr %s (%u) udp port %d: %s",
            fd, printable_ipv4_addr(ipv4_addr), ipv4_addr,
            udp_port_number, errno_string);
        close(fd);
        return -1;
    }

    /*
    ** all done
    */
    VLOG_DBG("udp_socket_create: created udp socket %d for %s (%u) port %d",
        fd, printable_ipv4_addr(ipv4_addr), ipv4_addr, udp_port_number);
    return fd;
}

/*
** Join/un-join a multicast group.
** Returns 0 upon success.
*/
static int
multicast_membership (int fd, uint ipv4_addr,
    uint ipv4_mcast_addr, int join)
{
    struct ip_mreqn mreq;
    int op;

    /*
    ** cannot join/drop a wildcard or non multicast addr
    */
    if (ipv4_addr_not_multicast(ipv4_mcast_addr)) {
        VLOG_ERR("multicast_membership: incorrect multicast addr %s (%u)",
            printable_ipv4_addr(ipv4_mcast_addr), ipv4_mcast_addr);
        return -1;
    }

    op = join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = ntohl(ipv4_mcast_addr);
    mreq.imr_address.s_addr = ntohl(ipv4_addr);
    if (setsockopt(fd, IPPROTO_IP, op, &mreq, sizeof(mreq))) {
        VLOG_ERR("multicast_membership: setsockopt %s call failed "
            "for fd %d addr %s (%u) maddr %s (%u): %s",
            join ? "JOIN" : "DROP",
            fd, printable_ipv4_addr(ipv4_addr), ipv4_addr,
            printable_ipv4_addr(ipv4_mcast_addr), ipv4_mcast_addr, errno_string);
        return -1;
    }

    VLOG_DBG("multicast_membership: fd %d ip %s %sjoined %s",
        fd, printable_ipv4_addr(ipv4_addr),
        join ? "" : "un-",
        printable_ipv4_addr(ipv4_mcast_addr));

    /* everything ok */
    return 0;
}

static int
join_multicast_group (int fd, uint ipv4_addr,
    uint ipv4_mcast_addr)
{
    return
        multicast_membership(fd, ipv4_addr, ipv4_mcast_addr, 1);
}

static int
drop_multicast_group (int fd, uint ipv4_addr,
    uint ipv4_mcast_addr)
{
    return
        multicast_membership(fd, ipv4_addr, ipv4_mcast_addr, 0);
}

static inline int
pkt_type2fd (sockets_table_t *tablep, packet_type_t pkt)
{
    return
        tablep->socket_entries_array[pkt].fd;
}

/*
** Start receiving packets of the desired type.
** These are multicasted so we join the multicast net and
** make sure we can receive on the corresponding udp port.
*/
static int
start_receiving_packets (sockets_table_t *tablep,
    packet_type_t pkt,
    uint ipv4_addr, uint ipv4_mcast_addr,
    packet_processing_function *ppfp)
{
    socket_entry_t *sep;
    int udp_port;

    sep = &(tablep->socket_entries_array[pkt]);
    if (sep->fd >= 0) {
        VLOG_DBG("already rcving %s packets; no op", printable_pkt_type(pkt));
        return 0;
    }

    udp_port = pkt_type_to_udp_port(pkt);
    sep->fd = udp_socket_create(ipv4_addr, udp_port);
    if (sep->fd < 0) {
        VLOG_ERR("could not snoop on %s; udp_socket_create failed",
            printable_pkt_type(pkt));
        return -1;
    }

    if (join_multicast_group(sep->fd, ipv4_addr, ipv4_mcast_addr)) {
        VLOG_ERR("could not join multicast for %s", printable_pkt_type(pkt));
        close(sep->fd);
        sep->fd = -1;
        return -1;
    }

    /* all done */
    sep->ipv4_addr = ipv4_addr;
    sep->ipv4_mcast_addr = ipv4_mcast_addr;
    sep->ppfp = ppfp;

    /* update the generic transmit fd with the latest opened socket fd */
    tablep->transmit_fd = sep->fd;

    VLOG_DBG("started snooping on %s packets on fd %d udp port %d",
        printable_pkt_type(pkt), sep->fd, udp_port);

    return 0;
}

/*
** Search the first file descriptor which is open (not -1)
** in the socket table.  This will almost always be used
** to transmit packets out from.  Note that even tho incoming
** packets can only be read from the socket which is bound
** to the correct udp port number, transmitting out a packet
** can be done from any open descriptor.
*/
static int
find_first_open_fd (sockets_table_t *tablep)
{
    packet_type_t a;

    for (a = FIRST_PKT; a < LAST_PKT; a++) {
        if (tablep->socket_entries_array[a].fd >= 0) {
            return tablep->socket_entries_array[a].fd;
        }
    }
    return -1;
}

static int
stop_receiving_packets (sockets_table_t *tablep,
    packet_type_t pkt)
{
    socket_entry_t *sep;
    int fd_was;

    sep = &(tablep->socket_entries_array[pkt]);
    if (sep->fd < 0) {
        VLOG_ERR("snoop fd for %s seems closed", printable_pkt_type(pkt));
        return -1;
    }

    /* remember what this fd was */
    fd_was = sep->fd;

    (void) drop_multicast_group(sep->fd, sep->ipv4_addr,
        sep->ipv4_mcast_addr);

    /* all done */
    close(sep->fd);
    sep->fd = -1;
    sep->ipv4_addr = 0;
    sep->ipv4_mcast_addr = 0;

    VLOG_DBG("stopped snooping on %s packets fd %d",
        printable_pkt_type(pkt), fd_was);

    /*
    ** if this was our general transmit fd,
    ** we have to find another open one
    */
    if (tablep->transmit_fd == fd_was) {
        VLOG_DBG("have to change transmit fd now; fd was %d", fd_was);
        fd_was = find_first_open_fd(tablep);
        sep->fd = fd_was;
        if (fd_was < 0) {
            VLOG_ERR("application stopped listening completely");
        } else {
            VLOG_DBG("new transmit fd is %d", fd_was);
        }
    }

    return 0;
}

static int
read_packet (int fd, uint ipv4_addr, int udp_port,
    ipc_packet_metadata_t *metap,
    char *data_buffer, int data_buffer_size,
    int do_not_block)
{
    struct sockaddr_in addr;
    struct iovec iov [2];
    struct msghdr mh;
    int bytes;

    if (fd < 0) {
        VLOG_ERR("fd is closed");
        return -1;
    }

    /* vector 0 is the metadata */
    iov[0].iov_base = (caddr_t) metap;
    iov[0].iov_len = sizeof(ipc_packet_metadata_t);

    /* vector 1 is the real user data */
    iov[1].iov_base = data_buffer;
    iov[1].iov_len = data_buffer_size;

    /* prepare address/port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ipv4_addr);
    addr.sin_port = htons(udp_port);

    /* prepare message header */
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = iov;
    mh.msg_iovlen = 2;
    mh.msg_name = (caddr_t) &addr;
    mh.msg_namelen = sizeof(addr);

    /* additional flags  */
    do_not_block = do_not_block ? MSG_DONTWAIT : 0;

    /* receive */
    bytes = recvmsg(fd, &mh, do_not_block);
    VLOG_DBG("received %d bytes from %s udp port %u",
        bytes, printable_ipv4_addr(ipv4_addr), udp_port);

    return bytes;
}

static int
write_packet (int fd, uint ipv4_addr, int udp_port,
    ipc_packet_metadata_t *metap,
    char *data, int data_len, int do_not_block)
{
    struct sockaddr_in addr;
    int bytes;
    struct iovec iov [2];
    struct msghdr mh;

    if (fd < 0) {
        VLOG_ERR("fd is closed");
        return -1;
    }

    /* vector 0 is the metadata */
    iov[0].iov_base = (caddr_t) metap;
    iov[0].iov_len = sizeof(ipc_packet_metadata_t);

    /* vector 1 is the real user data */
    iov[1].iov_base = data;
    iov[1].iov_len = data_len;

    /* prepare destination address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ipv4_addr);
    addr.sin_port = htons(udp_port);

    /* prepare message header */
    memset(&mh, 0, sizeof(mh));
    mh.msg_name = (caddr_t) &addr;
    mh.msg_namelen = sizeof(addr);
    mh.msg_iov = iov;
    mh.msg_iovlen = 2;

    /* additional flags  */
    do_not_block = do_not_block ? MSG_DONTWAIT : 0;

    /* send */
    bytes = sendmsg(fd, &mh, do_not_block);
    VLOG_DBG("sent %d bytes to %s port %d",
        bytes, printable_ipv4_addr(ipv4_addr), udp_port);

    return bytes;
}

static sockets_table_t my_socket_table = { 0 };
static sockets_table_t *my_tablep = &my_socket_table;
static uint g_multicast_address = 0;

/******************************************************************************
*******************************************************************************
**
** PUBLIC FUNCTIONS
**
*******************************************************************************
******************************************************************************/

#define CHECK_PKT_LIMITS(pkt) \
    if (invalid_pkt_type(pkt)) return -1

char *
printable_pkt_type (packet_type_t pkt)
{
    switch (pkt) {
        case STP_PKT: return "STP_PKT";
        case LLDP_PKT: return "LLDP_PKT";
        case LACP_PKT: return "LACP_PKT";
        case EXTERNAL: return "EXTERNAL";

        /* fall thru */
        case INVALID_PKT:
        case LAST_PKT:
        default: break;
    }
    return "INVALID_PKT";
}

void
ipc_packets_initialise (void)
{
    g_multicast_address = htonl(inet_addr(MCAST_ADDRESS));
    initialise_socket_entry_table(my_tablep);
}

int
ipc_packets_subscribe (packet_type_t pkt,
    packet_processing_function *ppfp)
{
    CHECK_PKT_LIMITS(pkt);
    return
        start_receiving_packets(my_tablep, pkt,
            INADDR_ANY, g_multicast_address, ppfp);
}

int
ipc_packets_unsubscribe (packet_type_t pkt)
{
    CHECK_PKT_LIMITS(pkt);
    return
        stop_receiving_packets(my_tablep, pkt);
}

int
ipc_packets_receive (packet_type_t pkt,
    ipc_packet_metadata_t *pkt_metadata,
    char *data_buffer, int buffer_size)
{
    CHECK_PKT_LIMITS(pkt);
    return
        read_packet(pkt_type2fd(my_tablep, pkt), INADDR_ANY, 0,
            pkt_metadata, data_buffer, buffer_size, 1);
}

int
ipc_packets_send (packet_type_t from_type, packet_type_t to_type,
    ipc_packet_metadata_t *pkt_metadata,
    char *packet_data, int packet_data_size)
{
    int fd_to_transmit_to;

    /* do all the checks */
    CHECK_PKT_LIMITS(to_type);
    fd_to_transmit_to =
        invalid_pkt_type(from_type) ?
            my_tablep->transmit_fd : pkt_type2fd(my_tablep, from_type);
    if (fd_to_transmit_to < 0) {
        fd_to_transmit_to = my_tablep->transmit_fd;
        if (fd_to_transmit_to < 0) {
            return -1;
        }
    }

    /* transmit it */
    return
        write_packet(fd_to_transmit_to, g_multicast_address,
            pkt_type_to_udp_port(to_type),
            pkt_metadata, packet_data, packet_data_size, 1);
}

/*
** Register all the open (>=0) file descriptors
** to be woken up by an event (poll).
*/
void
ipc_packets_wait (void)
{
    packet_type_t pkt;
    int fd;

    for (pkt = FIRST_PKT; pkt < LAST_PKT; pkt++) {
        fd = pkt_type2fd(my_tablep, pkt);
        if (fd >= 0) {
#ifndef IPC_PACKETS_TEST
            poll_fd_wait(fd, POLLIN);
#endif // IPC_PACKETS_TEST
            VLOG_DBG("added fd %d to poll loop for pkt %s",
                fd, printable_pkt_type(pkt));
        }
    }
}

#define MAX_PACKET_SIZE         (12 * 1024)
#define MAX_PACKETS_TO_PROCESS  8

/*
** For every open descriptor, read a packet &
** execute the user registered function on it.
** We should first check if a packet is actually
** available to read on the descriptor and only
** then read the packet but alternatively, we can
** attempt a non blocking read and see if anything
** was there in the first place.  The overhead would
** be approximately the same.
**
** Return value indicates how many packets were
** read & processed.
*/
int
ipc_packets_run (void)
{
    packet_type_t pkt;
    socket_entry_t *sep;
    int pak_size, pak_count, repeat_count;
    char *pakbuf;
    ipc_packet_metadata_t pkt_metadata;

    pakbuf = malloc(MAX_PACKET_SIZE);
    if (NULL == pakbuf) {
        VLOG_ERR("malloc for %d bytes failed", MAX_PACKET_SIZE);
        return 0;
    }

    /* total processed packets */
    pak_count = 0;

    /* for every pkt packet we are registered, read them */
    for (pkt = FIRST_PKT; pkt < LAST_PKT; pkt++) {

        sep = &my_tablep->socket_entries_array[pkt];

        /*
        ** For each type, try many times in case more than
        ** one packet may have been queued to be processed.
        ** As long as there are packets (pak_size > 0) and
        ** we have processed less than MAX_PACKETS_TO_PROCESS,
        ** keep on processing.  However, as soon as there are
        ** no more packets (pak_size <= 0), break out, no need
        ** to continue for this pkt, move on to the next one.
        */
        repeat_count = MAX_PACKETS_TO_PROCESS;
        do {
            pak_size = read_packet(sep->fd, INADDR_ANY, 0,
                            &pkt_metadata, pakbuf, MAX_PACKET_SIZE, 1);
            if (pak_size > 0) {
                VLOG_DBG("ipc_packets_run got a %s packet of size %d",
                    printable_pkt_type(pkt), pak_size);
                if (NULL != sep->ppfp) {
                    (sep->ppfp)(pkt, &pkt_metadata, pakbuf, pak_size);
                    VLOG_DBG("ipc_packets_run processed %s packet of size %d",
                        printable_pkt_type(pkt), pak_size);
                }
                pak_count++;
            }
        } while ((--repeat_count > 0) && (pak_size > 0));
    }

    /* get rid of this */
    free(pakbuf);

    /* total number of packets we processed */
    return pak_count;
}


