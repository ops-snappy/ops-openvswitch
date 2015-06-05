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

#ifndef IPC_PACKETS_H
#define IPC_PACKETS_H

/******************************************************************************
*******************************************************************************
**
** This file is designed to SELF compile.  Please maintain that
** property if you make any modifications to it.
**
*******************************************************************************
******************************************************************************/

/******************************************************************************
** These are packet types applications can send & receive.
** You can add to these without having to change anything else.
** Everything else will be automatically taken care of.
**
** DO NOT CHANGE INVALID_PKT, FIRST_PKT & LAST_PKT
*/
typedef enum packet_type_s {

    INVALID_PKT = -1,
    FIRST_PKT = 0,

    /* add your packet types here */
    STP_PKT = FIRST_PKT,
    LLDP_PKT,
    LACP_PKT,
    EXTERNAL,

    LAST_PKT

} packet_type_t;

/*
** Every packet handled by these APIs have this header ALWAYS
** in front of it.  This is the meta-data that is carried
** around between the processes.  If any other information
** needs to be transported, simply add to this structure.
*/
typedef struct ipc_packet_metadata_s {

    int flags;                 /* for future use */
    int pid;
    int interface_number;
    int vlan_number;

} ipc_packet_metadata_t;

/******************************************************************************
**
** Definition of the user supplied function which
** processes input packets.
*/
typedef void (packet_processing_function)
    (packet_type_t, ipc_packet_metadata_t*,
     char* pak_data, int pak_size);

/******************************************************************************
**
** Used for debug printing
*/
extern char *
printable_pkt_type (packet_type_t pkt);

/******************************************************************************
**
** Always call this FIRST to initialize
** the entire inter process packet manager.
*/
extern void
ipc_packets_initialise (void);

/******************************************************************************
**
** Start receiving these types of packets and when
** we do, call the function "ppfn" on them to process
** them.
**
** Return value is 0 for success.  Any other value
** indicates a fault.
*/
extern int
ipc_packets_subscribe (packet_type_t pkt,
    packet_processing_function *ppfn);

/******************************************************************************
**
** Opposite of "ipc_packets_subscribe" defined above.
*/
extern int
ipc_packets_unsubscribe (packet_type_t pkt);

/******************************************************************************
**
** Receive a packet of specified type.  Packet is placed
** into "data_buffer".  The function return value indicates
** the number of bytes read.  The "pkt_metadata" gets filled
** with the meta data of the incoming packet.
**
** The function return value indicates how many data bytes
** has been read.  A value of (<= 0) indicates either an
** error occured or no packet exists to read.
**
** This is a non blocking call.
*/
extern int
ipc_packets_receive (packet_type_t pkt,
    ipc_packet_metadata_t *pkt_metadata,
    char *data_buffer, int data_buffer_size);

/******************************************************************************
**
** Send a packet out of type "to_type".  The "from_type" parameter
** is used to specify the source udp port.  The "pkt_metadata" is
** specified by the sender.
**
** The function return value indicates how many data bytes
** has actually been successfully sent.  Like above, a return
** value of (<= 0) indicates an error.
*/
extern int
ipc_packets_send (packet_type_t from_type, packet_type_t to_type,
    ipc_packet_metadata_t *pkt_metadata,
    char *packet_data, int packet_data_size);

/******************************************************************************
**
** This call prepares all the file descriptors to wait on
** all registered incoming packet types.
*/
extern void
ipc_packets_wait (void);

/******************************************************************************
**
** This function processes all the packets which may have
** arrived from any of the applications we registered with.
** Return value indicates how many packets in total has
** been processed.
*/
extern int
ipc_packets_run (void);

#endif /* IPC_PACKETS_H */


