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

#include "p2acl.h"
#include "openvswitch/vlog.h"
#include "vswitchd/bridge.h"
#include "vswitchd/plugins/ops-classifier/include/ofproto-ops-classifier.h"
#include "acl.h"
#include "p2acl_colgrp.h"
#include "acl_port.h"
#include "ofproto_helps.h"

VLOG_DEFINE_THIS_MODULE(ops_cls_p2acl);

/*************************************************************
 * struct ops_cls_interface_info helper routines
 *************************************************************/
static void
ops_cls_interface_info_construct(struct ops_cls_interface_info *interface_info,
                                 const struct acl_port *port OVS_UNUSED,
                                 const struct port* bridgec_port OVS_UNUSED)
{
    memset(interface_info, 0, sizeof *interface_info);

    /* TODO: handle more interface types when we know how to */
    interface_info->interface = OPS_CLS_INTERFACE_PORT;
}

/*************************************************************
 * struct p2acl helper routines
 *************************************************************/
static void
p2acl_set_hw_acl(struct p2acl *p2acl, struct acl *acl)
{
    /* Only do something if the hw_acl is really changing */
    if (p2acl->hw_acl != acl) {
        if (p2acl->hw_acl) {
            /* remove myself from the old one */
            list_remove(&p2acl->acl_node);
        }
        p2acl->hw_acl = acl;
        if (p2acl->hw_acl) {
            /* add myself to the new one */
            list_push_back(&p2acl->hw_acl->p2acls, &p2acl->acl_node);
        }
    }
}

/*************************************************************
 * p2acl init/cleanup routines
 *************************************************************/
void
p2acl_construct(struct p2acl *p2acl, struct acl_port *p, off_t index)
{
    /* no allocation here. p2acl structs are stored in an array
       inside acl_port structs */
    p2acl->parent = p;
    p2acl->colgrp = &p2acl_colgrps[index];
    p2acl->hw_acl = NULL;
    list_init(&p2acl->acl_node);
}

void
p2acl_destruct(struct p2acl *p2acl)
{
    /* If we eventually hook into a polite shutdown mechanism, we'll
     * need to replace these asserts with a call to
     * p2acl_set_hw_acl(p2acl, NULL). If we ever do that, we should
     * also make sure that we teardown acl_ports (and therefore these
     * p2acl records) before we teardown the acl records.
     *
     * Only during a polite shutdown should we be doing low-level
     * teardown on PI records that are still interconnected.
     *
     * Until the day we support polite shutdown I prefer these asserts
     * to catch code that's doing bad things.
     */
    ovs_assert(!p2acl->hw_acl);
    ovs_assert(list_is_empty(&p2acl->acl_node));

    /* no deallocation here. p2acl structs are stored in an array
       inside acl_port structs */
}

/************************************************************
 * p2acl_cfg_create(), p2acl_cfg_update(), p2acl_cfg_delete() are the PI
 * p2acl CRUD routines.
 ************************************************************/
static void
p2acl_update_cfg_internal(struct p2acl *p2acl, struct port *bridgec_port)
{
    struct ops_cls_pd_status status;
    memset(&status, 0, sizeof status);
    struct ops_cls_interface_info interface_info;
    ops_cls_interface_info_construct(&interface_info,
                                     p2acl->parent, bridgec_port);
    int rc;
    const char *method_called = NULL;

    struct acl* acl;
    /* TODO: Start looking at want_version too.
     *       Short circuit if want_version == want_status_version.
     */
    const struct ovsrec_acl *ovsdb_acl =
        p2acl_colgrp_get_want(p2acl->colgrp, p2acl->parent->ovsdb_row);
    if (!ovsdb_acl) {
        acl = NULL;
        if (p2acl->hw_acl) {
            rc = call_ofproto_ops_cls_remove(p2acl->hw_acl,
                                             bridgec_port,
                                             &interface_info,
                                             p2acl->colgrp->direction,
                                             &status);
            method_called = "port_remove";
        } else {
            /* Nothing to delete in PD for this P2ACL */
        }
    } else {
        acl  = acl_lookup_by_uuid(&ovsdb_acl->header_.uuid);
        if (!acl) {
            /* This shouldn't happen because we currently process ACL
             * row changes before Port row changes. But once the
             * Change system is in place this really becomes
             * impossible. Changes will have dependencies and can
             * be reordered.
             */
            ovs_assert(0);
        }
        if (p2acl->hw_acl == acl) {
            /* Nothing to update in PD for this P2ACL */
        } else if (!p2acl->hw_acl) {
            VLOG_DBG("P2ACL %s:%s:%s applying %s",
                     p2acl->parent->name,
                     ops_cls_type_strings[p2acl->colgrp->type],
                     ops_cls_direction_strings[p2acl->colgrp->direction],
                     acl->name);
            rc = call_ofproto_ops_cls_apply(acl,
                                            bridgec_port,
                                            &interface_info,
                                            p2acl->colgrp->direction,
                                            &status);
            method_called = "port_apply";
        } else {
            VLOG_DBG("P2ACL %s:%s:%s replacing %s with %s",
                     p2acl->parent->name,
                     ops_cls_type_strings[p2acl->colgrp->type],
                     ops_cls_direction_strings[p2acl->colgrp->direction],
                     p2acl->hw_acl->name,
                     acl->name);
            rc = call_ofproto_ops_cls_replace(p2acl->hw_acl,
                                              acl,
                                              bridgec_port,
                                              &interface_info,
                                              p2acl->colgrp->direction,
                                              &status);
            method_called = "port_replace";
        }
    }

    if (method_called == NULL) {
        VLOG_DBG("P2ACL %s:%s:%s no PD call needed",
                 p2acl->parent->name,
                 ops_cls_type_strings[p2acl->colgrp->type],
                 ops_cls_direction_strings[p2acl->colgrp->direction]);
        /* TODO: report NoOp success to OVSDB */
    } else if (rc == 0) {
        /* success */
        VLOG_DBG("P2ACL %s:%s:%s -- PD %s succeeded",
                 p2acl->parent->name,
                 ops_cls_type_strings[p2acl->colgrp->type],
                 ops_cls_direction_strings[p2acl->colgrp->direction],
                 method_called);
        /* TODO: report success to OVSDB */
        p2acl_set_hw_acl(p2acl, acl);
    } else {
        /* failure */
        VLOG_DBG("P2ACL %s:%s:%s -- PD %s failed",
                 p2acl->parent->name,
                 ops_cls_type_strings[p2acl->colgrp->type],
                 ops_cls_direction_strings[p2acl->colgrp->direction],
                 method_called);
        /* TODO: report failure to OVSDB */
    }
}

void
p2acl_cfg_create(struct p2acl *p2acl, struct port *bridgec_port)
{
    VLOG_DBG("P2ACL %s:%s:%s - containing port row created",
             p2acl->parent->name,
             ops_cls_type_strings[p2acl->colgrp->type],
             ops_cls_direction_strings[p2acl->colgrp->direction]);

    /* no new/alloc to perform. Lifetime of p2acl is controlled by
       its containing acl_port */

    /* TODO: Remove temporary processing of P2ACL:C like an P2ACL:U */
    p2acl_update_cfg_internal(p2acl, bridgec_port);
}

void
p2acl_cfg_update(struct p2acl* p2acl, struct port *bridgec_port)
{
    VLOG_DBG("P2ACL %s:%s:%s - containing port row updated",
             p2acl->parent->name,
             ops_cls_type_strings[p2acl->colgrp->type],
             ops_cls_direction_strings[p2acl->colgrp->direction]);

    p2acl_update_cfg_internal(p2acl, bridgec_port);
}

/* This is a low-level routine. It does NOT interact with OVSDB. */
static void
p2acl_unapply_internal(struct p2acl* p2acl, struct port *bridgec_port)
{
    VLOG_DBG("P2ACL %s:%s:%s unapply",
             p2acl->parent->name,
             ops_cls_type_strings[p2acl->colgrp->type],
             ops_cls_direction_strings[p2acl->colgrp->direction]);

    ovs_assert(p2acl->hw_acl);

    /* Make the call down to the PD layer */
    struct ops_cls_pd_status status;
    memset(&status, 0, sizeof status);
    struct ops_cls_interface_info interface_info;
    ops_cls_interface_info_construct(&interface_info, p2acl->parent,
                                     bridgec_port);

    int rc = call_ofproto_ops_cls_remove(p2acl->hw_acl,
                                         bridgec_port,
                                         &interface_info,
                                         p2acl->colgrp->direction,
                                         &status);
    VLOG_DBG("P2ACL %s:%s:%s -- PD remove %s",
             p2acl->parent->name,
             ops_cls_type_strings[p2acl->colgrp->type],
             ops_cls_direction_strings[p2acl->colgrp->direction],
             rc==0 ? "succeeded" : "failed");

    /* Unapply (like delete) often has to be assumed to have succeeded,
     * even if lower levels said it failed. This is because unapply
     * & delete are often called as a knee-jerk reaction to noticing that
     * something has already been deleted.
     *
     * So, ignore rc and clear out our record from the acl.
     */
    p2acl_set_hw_acl(p2acl, NULL);
}

void
p2acl_cfg_delete(struct p2acl* p2acl, struct port *bridgec_port)
{
    VLOG_DBG("P2ACL %s:%s:%s deleted",
             p2acl->parent->name,
             ops_cls_type_strings[p2acl->colgrp->type],
             ops_cls_direction_strings[p2acl->colgrp->direction]);

    if (p2acl->hw_acl) {
        p2acl_unapply_internal(p2acl, bridgec_port);
    } else {
        VLOG_DBG("P2ACL %s:%s:%s no PD call needed",
                 p2acl->parent->name,
                 ops_cls_type_strings[p2acl->colgrp->type],
                 ops_cls_direction_strings[p2acl->colgrp->direction]);
    }

    /* There's nothing to log to OVSDB for a P2ACL:D, the OVSDB row
     * is already gone. */

    /* We don't release/free the p2acl* here. It's owned/managed
       by the acl_port structure. */
}

void
p2acl_unapply_for_acl_cfg_delete(struct p2acl* p2acl)
{
    VLOG_DBG("P2ACL %s:%s:%s upapply for ACL delete",
             p2acl->parent->name,
             ops_cls_type_strings[p2acl->colgrp->type],
             ops_cls_direction_strings[p2acl->colgrp->direction]);

    struct port *bridgec_port = global_port_lookup(p2acl->parent->name);
    if (!bridgec_port) {
        VLOG_ERR("INTERNAL ERROR: PORT %s not found. Unable to unapply p2acl",
                 p2acl->parent->name);
        return;
    }

    p2acl_unapply_internal(p2acl, bridgec_port);

    /* TODO: We must update OVSDB
     *       _cur must go to NULL
     *       _want_status must change too
     *         failed w/ reason = ACL deleted while applied
     */
}
