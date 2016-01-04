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

#ifndef __VSWITCHD__OPS_CLASSIFIER__ACL_PORT_H__
#define __VSWITCHD__OPS_CLASSIFIER__ACL_PORT_H__ 1

#include "hmap.h"
#include "uuid.h"
#include "p2acl_colgrp.h"
#include "p2acl.h"

/*************************************************************
 * acl_port structures
 *
 * Structures to store ACL-specific information about each port
 *
 * There should be one of these for every 'struct port'
 * maintained by bridge.c.
 *
 * TODO: Once switchd refactor is complete, we should use their
 * methods to track changes in bridge.c managed port structures.
 * For now we track the Port OVSDB table ourselves and then go
 * query bridge.c to get it's port structure right before making
 * PD calls.
 *************************************************************/
struct acl_port {
    struct hmap_node   all_node_uuid; /* In 'all_acl_ports'. */
    struct uuid        uuid;

    /* TEMPORARY: So we can find 'struct port' from bridge.c. */
    /* TODO: After switchd refactor, change this to be a
     *       'struct port *'
     *       Can't store it now, because we're not listening
     *       to bridge.c port CRUD events.
     */
    const char        *name;

    /* Hold all of my p2acl records internally, no need to
       allocate them separately. */
    struct p2acl p2acls[NUM_P2ACL_COLGRPS];

    const struct ovsrec_port *ovsdb_row;
    unsigned int       delete_seqno; /* mark/sweep to identify deleted */
};

/*************************************************************
 * acl_port search routines
 *************************************************************/
struct acl_port *acl_port_lookup_by_uuid(const struct uuid* uuid);

/************************************************************
 * Top level routine to check if a port's ACLs need to reconfigure
 ************************************************************/
void acl_port_maybe_reconfigure(void);

#endif  /* __VSWITCHD__OPS_CLASSIFIER__ACL_PORT_H__ */
