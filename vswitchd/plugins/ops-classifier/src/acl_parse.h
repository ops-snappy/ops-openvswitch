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

#ifndef __VSWITCHD__OPS_CLASSIFIER__ACL_PARSE_H__
#define __VSWITCHD__OPS_CLASSIFIER__ACL_PARSE_H__ 1

#include <stdlib.h>
#include <ctype.h>
#include "vswitchd/plugins/ops-classifier/include/ofproto-ops-classifier.h"
#include "acl.h"

#define ACL_PROTOCOL_ICMP    1
#define ACL_PROTOCOL_IGMP    2
#define ACL_PROTOCOL_TCP     6
#define ACL_PROTOCOL_UDP     17
#define ACL_PROTOCOL_GRE     47
#define ACL_PROTOCOL_ESP     50
#define ACL_PROTOCOL_AH      51
#define ACL_PROTOCOL_ICMPV6  58
#define ACL_PROTOCOL_PIM     103
#define ACL_PROTOCOL_SCTP    132
#define ACL_PROTOCOL_INVALID 255

in_addr_t ipv4_mask_create(uint8_t prefix_len);
bool acl_parse_ipv4_address(const char *in_address,
                            enum ops_cls_list_entry_flags flag,
                            uint32_t *flags,
                            struct in_addr *v4_addr,
                            struct in_addr *v4_mask,
                            enum ops_cls_addr_family *family);
bool acl_parse_protocol(const char *in_proto,
                        enum ops_cls_list_entry_flags flag,
                        uint32_t *flags,
                        uint8_t *proto);
bool acl_parse_actions(const char *in_action,
                       struct ops_cls_list_entry_actions *actions);
bool acl_parse_l4_port(const char *in_port,
                       uint16_t *port);
bool acl_parse_l4_operator(const char *in_op,
                           enum ops_cls_list_entry_flags flag,
                           uint32_t *flags,
                           enum ops_cls_L4_operator *op);

#endif  /* __VSWITCHD__OPS_CLASSIFIER__ACL_PARSE_H__ */
