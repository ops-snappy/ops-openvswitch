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

typedef unsigned int uint;

char *stp_message = "SERVER sent STP message";
char *lldp_message = "SERVER sent LLDP message";
char *lacp_message = "SERVER sent LACP message";

#define INPUT_SIZE		128
char input [INPUT_SIZE];
ipc_packet_metadata_t sent_meta = { 0 };
ipc_packet_metadata_t received_meta = { 0 };
int transmit = 0;
int receive = 0;

void dump_meta (ipc_packet_metadata_t *metap)
{
    printf("\tmeta.pid %d, meta.if %d, meta.vlan %d\n",
        metap->pid, metap->interface_number, metap->vlan_number);
}

void read_possible_packets (void)
{
    int i, bytes;

    for (i = 0; i < 50; i++) {
	bytes = ipc_packets_receive(EXTERNAL, &received_meta, 
            input, INPUT_SIZE);
	if (bytes > 0) {
	    input[bytes] = 0;
	    printf("received packet %d: <%s> from client\n", receive, input);
            receive++;
            dump_meta(&received_meta);
	} else {
	    // printf("SERVER did NOT receive any packets");
	}
    }
}

int main (int argc, char *argv[])
{
    int bytes;
    int pid = getpid();

    sent_meta.pid = pid;

    ipc_packets_initialise();
    if (ipc_packets_subscribe(EXTERNAL, NULL)) {
	printf("server group add for %s failed\n", 
            printable_pkt_type(EXTERNAL));
        exit(1);
    }
    while (1) {

        sent_meta.interface_number++;
        sent_meta.vlan_number++;

	bytes = ipc_packets_send(EXTERNAL, STP_PKT, 
	    &sent_meta, stp_message, strlen(stp_message)+1);
	printf("sent packet %d: <%s> (%d bytes actually went out)\n",
	    transmit++, stp_message, bytes);
	read_possible_packets();

	bytes = ipc_packets_send(EXTERNAL, LLDP_PKT,
	    &sent_meta, lldp_message, strlen(lldp_message)+1);
	printf("sent packet %d: <%s> (%d bytes actually went out)\n",
	    transmit++, lldp_message, bytes);
	read_possible_packets();

	bytes = ipc_packets_send(EXTERNAL, LACP_PKT,
	    &sent_meta, lacp_message, strlen(lacp_message)+1);
	printf("sent packet %d: <%s> (%d bytes actually went out)\n",
	    transmit++, lacp_message, bytes);
	read_possible_packets();


	printf("sleeping 5 seconds....");
	printf("\n\n\n\n\n");
	sleep(5);
    }

    exit(0);
}
