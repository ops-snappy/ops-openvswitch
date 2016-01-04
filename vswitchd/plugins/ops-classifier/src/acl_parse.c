/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

#include "acl_parse.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ops_cls_acl_parse);

static bool
protocol_is_number(const char *in_proto)
{
    /* Null check. May not be necessary here */
    if (!*in_proto) {
        return false;
    }

    /* Check if every character in the string is a digit */
    while (*in_proto) {
        if (!isdigit(*in_proto)) {
            return false;
        }
        ++in_proto;
    }

    return true;
}

static uint8_t
protocol_get_number_from_name(const char *in_proto)
{
    uint8_t protocol = ACL_PROTOCOL_INVALID;

    if (!in_proto) {
        VLOG_DBG("Null protocol string specified");
        return protocol;
    }

    if (!strcmp(in_proto, "ah")) {
        protocol = ACL_PROTOCOL_AH;
    } else if (!strcmp(in_proto, "esp")) {
        protocol = ACL_PROTOCOL_ESP;
    } else if (!strcmp(in_proto, "icmp")) {
        protocol = ACL_PROTOCOL_ICMP;
    } else if (!strcmp (in_proto, "icmpv6")) {
        protocol = ACL_PROTOCOL_ICMPV6;
    } else if (!strcmp (in_proto, "igmp")) {
        protocol = ACL_PROTOCOL_IGMP;
    } else if (!strcmp (in_proto, "pim")) {
        protocol = ACL_PROTOCOL_PIM;
    } else  if (!strcmp (in_proto, "sctp")) {
        protocol = ACL_PROTOCOL_SCTP;
    } else if (!strcmp (in_proto, "tcp")) {
        protocol = ACL_PROTOCOL_TCP;
    } else if (!strcmp (in_proto, "udp")) {
        protocol = ACL_PROTOCOL_UDP;
    } else {
        VLOG_DBG("Invalid protocol specified %s", in_proto);
        protocol = ACL_PROTOCOL_INVALID;
    }

    return protocol;
}

in_addr_t
ipv4_mask_create(uint8_t prefix_len)
{
    /* bit twiddling ideas from:
     * http://stackoverflow.com/questions/20263860/ipv4-prefix-length-to-netmask
     *
     *          1 << (32 - prefix_len)
     * 32 -> 0b00000000 00000000 00000000 00000001
     * 24 -> 0b00000000 00000000 00000001 00000000
     *  1 -> 0b10000000 00000000 00000000 00000000
     *
     *          (1 << (32 - prefix_len)) - 1
     * 32 -> 0b00000000 00000000 00000000 00000000
     * 24 -> 0b00000000 00000000 00000000 11111111
     *  1 -> 0b01111111 11111111 11111111 11111111
     *
     *        ~((1 << (32 - prefix_len)) - 1)
     * 32 -> 0b11111111 11111111 11111111 11111111
     * 24 -> 0b11111111 11111111 11111111 00000000
     *  1 -> 0b10000000 00000000 00000000 00000000
     */
    return prefix_len ? htonl(~((0x1u << (32 - prefix_len)) - 1)) : 0;
}

bool
acl_parse_ipv4_address(const char *in_address,
                   enum ops_cls_list_entry_flags flag,
                   uint32_t *flags,
                   struct in_addr *v4_addr,
                   struct in_addr *v4_mask,
                   enum ops_cls_addr_family *family)
{
    /* TODO: support more formats
     *   - For now only support x.x.x.x and x.x.x.x/d
     */
    if (!strcmp(in_address, "any")) {
        /* we leave zero'd fields alone for "any" */
    } else {
        *flags |= flag;
        *family = OPS_CLS_AF_INET;

        /* see if we have the 10.0.0.1/24 format */
        char *copy_address = NULL;
        const char *hstr;
        char *pstr = strchr(in_address, '/');
        const uint8_t max_prefix_len = 32;
        int prefix_len;
        if (pstr) {
            /* make a copy we can munge */
            copy_address = xstrdup(in_address);
            pstr = copy_address + (pstr - in_address);
            hstr = copy_address;

            *pstr++ = '\0'; /* overwrite '/' to terminate hstr */
            prefix_len = atoi(pstr);
            if (prefix_len > max_prefix_len) {
                VLOG_ERR("Bad prefixlen %d > %d", prefix_len, max_prefix_len);
                free(copy_address);
                return false;
            }
        } else {
            /* plain hostname, just work off original in_address */
            hstr = in_address;

            prefix_len = max_prefix_len;
        }

        /* Set the mask based on the prefix_len */
        v4_mask->s_addr = ipv4_mask_create(prefix_len);

        /* parse the actual address part */
        if (inet_pton(AF_INET, hstr, v4_addr) == 0) {
            VLOG_ERR("Invalid ip address %s", in_address);
            free(copy_address);
            return false;
        }

        free(copy_address);

    }

    return true;
}

bool
acl_parse_protocol(const char *in_proto,
                   enum ops_cls_list_entry_flags flag,
                   uint32_t *flags,
                   uint8_t *proto)
{
    if (!strcmp(in_proto, "any")) {
        /* we leave zero'd fields alone for "any" */
    } else {
        *flags |= flag;

        /* Check if the protocol is a number */
        if (protocol_is_number(in_proto)) {
            *proto = strtoul(in_proto, NULL, 10);
        } else {
            /* Protocol is a name. Map it to the correct protocol number */
            *proto = protocol_get_number_from_name(in_proto);
            if (*proto == ACL_PROTOCOL_INVALID)
            {
                VLOG_ERR("Invalid protocol %s", in_proto);
                return false;
            }
        }
    }
    VLOG_DBG("classifier: protocol = %d", *proto);
    return true;
}

bool
acl_parse_actions(const char *in_action,
                  struct ops_cls_list_entry_actions *actions)
{
    /* TODO: handle empty action */
    /* TODO: handle conflicting actions (e.g. permit and deny) */

    if (strstr(in_action, "permit")) {
        actions->action_flags |= OPS_CLS_ACTION_PERMIT;
    }

    if (strstr(in_action, "deny")) {
        actions->action_flags |= OPS_CLS_ACTION_DENY;
    }

    if (strstr(in_action, "log")) {
        actions->action_flags |= OPS_CLS_ACTION_LOG;
    }

    if (strstr(in_action, "count")) {
        actions->action_flags |= OPS_CLS_ACTION_COUNT;
    }

    return true;
}

bool
acl_parse_l4_port(const char *in_port, uint16_t *port)
{
    /* TODO: check return codes to detect if not even in integer format */
    uint64_t tmp = strtoul(in_port, NULL, 10);
    if (tmp > UINT16_MAX) {
        VLOG_ERR("Invalid L4 port %s", in_port);
        return false;
    }
    *port = tmp;

    VLOG_DBG("classifier: L4 port = %u", *port);
    return true;
}

/* TODO: Remove these once the schema parser can generate them for us */
#ifndef OPS_CLS_L4_PORT_OP_EQ_STR
#define OPS_CLS_L4_PORT_OP_EQ_STR "eq"
#define OPS_CLS_L4_PORT_OP_NEQ_STR "neq"
#define OPS_CLS_L4_PORT_OP_LT_STR "lt"
#define OPS_CLS_L4_PORT_OP_GT_STR "gt"
#define OPS_CLS_L4_PORT_OP_RANGE_STR "range"
#endif

bool
acl_parse_l4_operator(const char *in_op, enum ops_cls_list_entry_flags flag,
                      uint32_t *flags, enum ops_cls_L4_operator *op)
{
    *flags |= flag;

    if (strcmp(OPS_CLS_L4_PORT_OP_EQ_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_EQ;
    } else if (strcmp(OPS_CLS_L4_PORT_OP_NEQ_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_NEQ;
    } else if (strcmp(OPS_CLS_L4_PORT_OP_LT_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_LT;
    } else if (strcmp(OPS_CLS_L4_PORT_OP_GT_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_GT;
    } else if (strcmp(OPS_CLS_L4_PORT_OP_RANGE_STR, in_op)==0) {
        *op = OPS_CLS_L4_PORT_OP_RANGE;
    } else {
        VLOG_ERR("Invalid L4 operator %s", in_op);
        return false;
    }
    VLOG_DBG("classifier: L4 operator = %d", *op);
    return true;
}
