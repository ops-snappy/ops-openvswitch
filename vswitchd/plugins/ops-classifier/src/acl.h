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

#ifndef __VSWITCHD__OPS_CLASSIFIER__ACL_H__
#define __VSWITCHD__OPS_CLASSIFIER__ACL_H__ 1

#include <stdbool.h>
#include "hmap.h"
#include "uuid.h"
#include "list.h"
#include "vswitchd/plugins/ops-classifier/include/ofproto-ops-classifier.h"

struct classifier_list;
struct ops_cls_list;

/*************************************************************
 * acl structures
 *************************************************************/
struct acl {
    struct hmap_node   all_node_uuid;   /* In 'all_acls_by_uuid'. */

    /* members with information "about" me */
    struct uuid        uuid;
    const char        *name;
    enum ops_cls_type  type;

    /* members for working with OVSDB */
    const struct ovsrec_acl *ovsdb_row;
    unsigned int       delete_seqno; /* mark/sweep to identify deleted */

    /* members represending my cached PI state */
    struct ovs_list p2acls;    /* List of struct p2acls. */
    struct ops_cls_list *want_pi; /* temporary until Change system in place */
};

/*************************************************************
 * acl lookup routines
 *************************************************************/
struct acl* acl_lookup_by_uuid(const struct uuid* uuid);

/************************************************************
 * Top level routine to check if ACL's need to reconfigure
 ************************************************************/
void acl_maybe_reconfigure(void);

#endif  /* __VSWITCHD__OPS_CLASSIFIER__ACL_H__ */
