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
#include <sys/shm.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sched.h>
#include <stdarg.h>

#include "../ipc_packets.h"

#define SIZE	256
char buffer[SIZE];
char send_buffer [64];
int pid;

ipc_packet_metadata_t received_meta = { 0 };
ipc_packet_metadata_t sent_meta = { 0 };

void dump_meta (ipc_packet_metadata_t *metap)
{
    printf("\tmeta.pid %d, meta.if %d, meta.vlan %d\n",
        metap->pid, metap->interface_number, metap->vlan_number);
}

packet_type_t parse_arg (char *arg) 
{
    if (strcmp(arg, "stp") == 0) return STP_PKT;
    if (strcmp(arg, "lldp") == 0) return LLDP_PKT;
    if (strcmp(arg, "lacp") == 0) return LACP_PKT;
    return INVALID_PKT;
}

void send_response (void)
{
    int bytes;

    sent_meta.interface_number++;
    sent_meta.vlan_number++;

    bytes = ipc_packets_send(-1, EXTERNAL, 
	&sent_meta, send_buffer, strlen(send_buffer)+1);
    printf("APP %d sent %d bytes <%s> to server\n", 
	pid, bytes, send_buffer);
}

int main (int argc, char *argv[])
{
    int i;
    int bytes;
    packet_type_t apps [10];

    if (argc < 2) {
	printf("usage: %s [stp] [lldp] [lacp]\n", argv[0]);
	exit(1);
    }

    pid = getpid();
    sent_meta.pid = pid;
    ipc_packets_initialise();
    for (i = 1; i < argc; i++) {
	apps[i] = parse_arg(argv[i]);
	if (ipc_packets_subscribe(apps[i], NULL)) {
	    printf("app %d group add for %s failed\n", 
		pid, printable_pkt_type(apps[i]));
            exit(0);
	} else {
	    printf("app %d successully added to %s group\n",
		pid, printable_pkt_type(apps[i]));
	}
    }

    /* prepare a message to send */
    sprintf(send_buffer, "APP %d sent this message", pid);

    while (1) {
	for (i = 1; i < argc; i++) {
	    memset(buffer, 0, SIZE);
	    bytes = ipc_packets_receive(apps[i], &received_meta, buffer, SIZE);
	    if (bytes > 0) {
		printf("APP %d received <%s>\n", pid, buffer);
                dump_meta(&received_meta);
		send_response();
		printf("\n\n\n");
	    } else if (bytes < 0) {
		// printf("APP %d reading %s packet failed: %s\n", 
		    // pid, printable_pkt_type(apps[i]), (strerror(errno)));
	    }
	}
    }

    exit(0);
}
