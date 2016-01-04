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

#ifndef __VSWITCHD__OPS_CLASSIFIER__P2ACL_COLGRP_H__
#define __VSWITCHD__OPS_CLASSIFIER__P2ACL_COLGRP_H__ 1

#include <unistd.h>

/* TODO: shorten these paths once we build in our own plugin */
#include "vswitchd/plugins/ops-classifier/include/ofproto-ops-classifier.h"

struct ovsrec_port;
struct ovsrec_acl;
struct smap;

/*************************************************************
 * p2acl_colgrp
 *
 * Data structure to ease access to the many P2ACL field
 * "quartets" stored in the ovsrec_port table.
 *
 * For now, access to IDL generated fields cannot cleanly be
 * accomplished solely via row pointers and column pointers.
 * Access is only provided via direct access to individualy
 * named structure members and setter functions (e.g
 * ovsrec_port_set_aclv4_in_cur(). This means that
 * a function coded to work with the aclv4_in_cur field cannot
 * also be used to access the aclv4_out_cur field.
 *
 * This structure, and it's associated getters/setters solve that
 * problem. Functions coded to work with p2acl_colgp_get_cur()
 * and p2acl_colgrp_set_cur() will be able to work with the _cur
 * field of any p2acl "quartet".
 ************************************************************/
struct p2acl_colgrp {
    enum ops_cls_type type;
    enum ops_cls_direction direction;

    /* column pointer */
    struct ovsdb_idl_column *column_cur;
    struct ovsdb_idl_column *column_want;
    struct ovsdb_idl_column *column_want_version;
    struct ovsdb_idl_column *column_want_status;

    /* Offset to the fields inside IDL-generated 'struct ovsrec_port' */
    off_t offset_cur;
    off_t offset_want;
    off_t offset_want_version;
    off_t offset_want_status;

    /* pointers to IDL-generated setter functions */
    void (*set_cur)(const struct ovsrec_port *,
                    const struct ovsrec_acl *cur);
    void (*set_want)(const struct ovsrec_port *,
                     const struct ovsrec_acl *want);
    void (*set_want_version)(const struct ovsrec_port *,
                             int64_t want_version);
    void (*set_want_status)(const struct ovsrec_port *,
                            const struct smap *want_status);
};

#define NUM_P2ACL_COLGRPS 1
extern struct p2acl_colgrp p2acl_colgrps[NUM_P2ACL_COLGRPS];

void p2acl_colgroup_init(void);

/***** Getters *****/
const struct ovsrec_acl* p2acl_colgrp_get_cur(
    const struct p2acl_colgrp *colgrp, const struct ovsrec_port *port);
const struct ovsrec_acl* p2acl_colgrp_get_want(
    const struct p2acl_colgrp *colgrp, const struct ovsrec_port *port);
int64_t p2acl_colgrp_get_want_version(
    const struct p2acl_colgrp *colgrp, const struct ovsrec_port *port);
const struct smap* p2acl_colgrp_get_want_status(
    const struct p2acl_colgrp *colgrp, const struct ovsrec_port *port);

/***** Setters *****/
void p2acl_colgrp_set_cur(const struct p2acl_colgrp *colgrp,
                          const struct ovsrec_port *port,
                          const struct ovsrec_acl *cur);
void p2acl_colgrp_set_want(const struct p2acl_colgrp *colgrp,
                           const struct ovsrec_port *port,
                           const struct ovsrec_acl *want);
void p2acl_colgrp_set_want_version(const struct p2acl_colgrp *colgrp,
                                   const struct ovsrec_port *port,
                                   int64_t want_version);
void p2acl_colgrp_set_want_status(const struct p2acl_colgrp *colgrp,
                                  const struct ovsrec_port *port,
                                  const struct smap *want_status);

#endif  /* __VSWITCHD__OPS_CLASSIFIER__P2ACL_COLGRP_H__ */
