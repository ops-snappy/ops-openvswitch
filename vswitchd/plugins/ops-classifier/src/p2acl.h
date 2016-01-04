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

#ifndef __VSWITCHD__OPS_CLASSIFIER__P2ACL_H__
#define __VSWITCHD__OPS_CLASSIFIER__P2ACL_H__ 1

#include "list.h"

struct acl_port;
struct p2acl_colgrp;
struct acl;
struct port; /* from bridge.h */

/*************************************************************
 * p2acl structures
 *
 * This is stored in an arrary inside acl_port.
 *************************************************************/
struct p2acl {
    /* points back to my parent */
    struct acl_port *parent;

    /* Reference the meta-data about this p2acl: */
    /*    type, dir, ovsdb_colgrpdef */
    const struct p2acl_colgrp *colgrp;

    struct acl  *hw_acl; /* No ownership. Just borrowing pointer */
    struct ovs_list acl_node; /* For linking into hw_acl's p2acls list. */
};

/* low level reoutines to init/de-init p2acl structures.
   There perform no PD calls */
void p2acl_construct(struct p2acl *p2acl, struct acl_port *p, off_t index);
void p2acl_destruct(struct p2acl *p2acl);


/* CRUD calls for p2acls. This is where the PD calls get made */
void p2acl_cfg_create(struct p2acl *p2acl, struct port *bridgec_port);
void p2acl_cfg_update(struct p2acl* p2acl, struct port *bridgec_port);
void p2acl_cfg_delete(struct p2acl* p2acl, struct port *bridgec_port);
void p2acl_unapply_for_acl_cfg_delete(struct p2acl* p2acl);

#endif  /* __VSWITCHD__OPS_CLASSIFIER__P2ACL_H__ */
