/*
 * Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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


#include "openvswitch/vlog.h"
#include "vswitchd/bridge.h"
#include "p2acl_colgrp.h"
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "vswitchd/plugins/ops-classifier/include/ops-classifier.h"

void acl_maybe_reconfigure(void);
void acl_port_maybe_reconfigure(void);

VLOG_DEFINE_THIS_MODULE(ops_cls);

/*
 * Top Level reconfigure function for ops-classifier plugin
 */
void
ops_cls_reconfigure(void)
{
    if (switchd_restarted) {
        VLOG_DBG("reconfigure() called: switchd_restarted");
#ifdef TODO_OVSDB_RECONNECTED
        ovs_assert(ovsdb_reconnected);
#endif // TODO_OVSDB_RECONNECTED
    } else if (ovsdb_reconnected) {
        VLOG_DBG("reconfigure() called: ovsdb_reconnected");
    } else {
        VLOG_DBG("reconfigure() called");
    }

    /* Temporary until the full Change system is in place.  Other
     * temporary code currently relies on the fact that ALC changes
     * are processed before Port changes.
     */
    acl_maybe_reconfigure();
    acl_port_maybe_reconfigure();
}

void
ops_cls_init(void)
{
    p2acl_colgroup_init();

    /* tell IDL layer about our "write-only" Port table fields */
    for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
        ovsdb_idl_omit_alert(idl, p2acl_colgrps[i].column_cur);
        ovsdb_idl_omit_alert(idl, p2acl_colgrps[i].column_want_status);
    }

    /* ACL table fields nobody uses */
    /* TODO: pull these out of the schema */
    ovsdb_idl_omit(idl, &ovsrec_acl_col_other_config);
    ovsdb_idl_omit(idl, &ovsrec_acl_col_external_ids);

    /* ACL table fields that are write-only (at least for now) */
    /* TODO: once we listen to cur/want_status to know when we can prune
     * our internal in_hw data, we'll need to remove these so we can get
     * notifications when they change.
     */
    ovsdb_idl_omit(idl, &ovsrec_acl_col_cur);
    ovsdb_idl_omit(idl, &ovsrec_acl_col_want_status);
}
