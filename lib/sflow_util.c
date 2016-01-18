/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "collectors.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socket-util.h"
#include "sset.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(sflow_util);

/* TODO: Can 'fds' be part of SFLReceiver?. The list of 'targets' is obtained
from ofproto_sflow_options.  */
struct collectors {
    int *fds;                     /* Sockets. */
    size_t n_fds;                 /* Number of sockets. */
};

/* Opens the targets specified in 'targets' for sending UDP packets.  This is
 * useful for e.g. sending NetFlow or sFlow packets.  Returns 0 if successful,
 * otherwise a positive errno value if opening at least one collector failed.
 *
 * Each target in 'targets' should be a string in the format "<host>[:<port>]".
 * <port> may be omitted if 'default_port' is nonzero, in which case it
 * defaults to 'default_port'.
 *
 * '*collectorsp' is set to a null pointer if no targets were successfully
 * added, otherwise to a new collectors object if at least one was successfully
 * added.  Thus, even on a failure return, it is possible that '*collectorsp'
 * is nonnull, and even on a successful return, it is possible that
 * '*collectorsp' is null, if 'target's is an empty sset. */
int
collectors_create(const struct sset *targets, uint16_t default_port,
                  struct collectors **collectorsp)
{
    struct collectors *c;
    const char *name;
    int retval = 0;

    c = xmalloc(sizeof *c);
    c->fds = xmalloc(sizeof *c->fds * sset_count(targets));
    c->n_fds = 0;
    SSET_FOR_EACH (name, targets) {
        int error;
        int fd;

        error = inet_open_active(SOCK_DGRAM, name, default_port, NULL, &fd, 0);
        if (fd >= 0) {
            c->fds[c->n_fds++] = fd;
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_WARN_RL(&rl, "couldn't open connection to collector %s (%s)",
                         name, ovs_strerror(error));
            if (!retval) {
                retval = error;
            }
        }
    }

    if (c->n_fds) {
        *collectorsp = c;
    } else {
        collectors_destroy(c);
        *collectorsp = NULL;
    }

    return retval;
}

/* Destroys 'c'. */
void
collectors_destroy(struct collectors *c)
{
    if (c) {
        size_t i;

        for (i = 0; i < c->n_fds; i++) {
            close(c->fds[i]);
        }
        free(c->fds);
        free(c);
    }
}

/* Sends the 'n'-byte 'payload' to each of the collectors in 'c'. */
void
collectors_send(const struct collectors *c, const void *payload, size_t n)
{
    if (c) {
        size_t i;

        for (i = 0; i < c->n_fds; i++) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            if (send(c->fds[i], payload, n, 0) == -1) {
                char *s = describe_fd(c->fds[i]);
                VLOG_WARN_RL(&rl, "%s: sending to collector failed (%s)",
                             s, ovs_strerror(errno));
                free(s);
            }
        }
    }
}

int
collectors_count(const struct collectors *c)
{
    return c ? c->n_fds : 0;
}

static char *
rawdata_to_hex(const void *data, size_t n)
{
    char *hex = xmalloc(n+1);
    size_t i;

    for (i=n; i; i--) {
        snprintf(hex, sizeof(char), "%0X ", data);
        data++;
    }
    hex[n] = '\0';

    return hex;
}

SFLReceivers_pack_send(SFLAgent *ops_agent, const void *payload, size_t n)
{
    if (ops_agent == NULL) {
        VLOG_ERR("%s:%d: Invalid sFlow agent passed.", __FUNCTION__, __LINE__);
        return;
    }

    //VLOG_ERR("%s:%d: Payload: %s of size: %d", __FUNCTION__, __LINE__,
    //        rawdata_to_hex(payload n), n);

    SFLReceiver *rcv = ops_agent->receivers;
    for(; rcv; rcv=rcv->nxt) {
    }

    return;
}

/* Fn to write received sample pkt to buffer. Wrapper for
 * sfl_sampler_writeFlowSample() routine. */
void ops_sflow_write_sampled_pkt(opennsl_pkt_t *pkt)
{
    SFL_FLOW_SAMPLE_TYPE    fs;
    SFLFlow_sample_element  hdrElem;
    SFLSampled_header       *header;
    SFLSampler              *sampler;

    if (!pkt) {
        VLOG_ERR("%s:%d; NULL sFlow pkt received.", __FUNCTION__, __LINE__);
        return;
    }

    /* sFlow Agent is uninitialized. Error condition or it's not enabled
     * yet. */
    if (!ops_sflow_agent) {
        VLOG_ERR("%s:%d; sFlow Agent uninitialized.", __FUNCTION__, __LINE__);
        return;
    }

    sampler = ops_sflow_agent->samplers;
    if (!sampler) {
        VLOG_ERR("%s:%d; Sampler on sFlow Agent uninitialized.", __FUNCTION__, __LINE__);
        return;
    }

    /* Sampled header. */
    /* Code from ofproto-dpif-sflow.c */
    memset(&hdrElem, 0, sizeof hdrElem);
    hdrElem.tag = SFLFLOW_HEADER;
    header = &hdrElem.flowType.header;
    header->header_protocol = SFLHEADER_ETHERNET_ISO8023;

    /* The frame_length should include the Ethernet FCS (4 bytes),
     * but it has already been stripped, so we need to add 4 here.
     *
     * In OpenNSL, there are two length's (pkt_len and tot_len). tot_len
     * includes FCS (4 bytes) and pkt_len = tot_len-4.
     * TODO: Confirm this theory with Broadcomm.
     */
    header->frame_length = pkt->tot_len;

    /* Ethernet FCS stripped off. */
    header->stripped = 4;
    header->header_length = MIN(header->frame_length,
                                sampler->sFlowFsMaximumHeaderSize);

    /* TODO: OpenNSL saves incoming data blocks as an array of structs
     * (containing {len, data} pairs). Is pointing 'header_bytes' to
     * beginning of this array sufficient? */
    header->header_bytes = (uint8_t *)pkt->pkt_data;

    /* Submit the flow sample to be encoded into the next datagram. */
    SFLADD_ELEMENT(&fs, &hdrElem);
    sfl_sampler_writeFlowSample(sampler, &fs);
}
