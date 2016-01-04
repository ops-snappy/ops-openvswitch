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

#include "ofproto_helps.h"

#include <errno.h>
#include <config.h>
#include "vswitchd/plugins/ops-classifier/include/ofproto-ops-classifier.h"
#include "ofproto/ofproto-provider.h"
#include "openvswitch/vlog.h"
#include "vswitchd/bridge.h"
#include "acl.h"

VLOG_DEFINE_THIS_MODULE(ops_cls_pd_calls);

const char * const ops_cls_type_strings[] = {
    "INVALID",
    "ACL_V4",
    "ACL_V6"
};

const char * const ops_cls_direction_strings[] = {
    "INVALID",
    "IN",
    "OUT"
};

struct ops_cls_list*
ops_cls_list_new(void)
{
    struct ops_cls_list *list = xzalloc(sizeof *list);
    return list;
}

void
ops_cls_list_delete(struct ops_cls_list *list)
{
    if (list) {
        free(CONST_CAST(char*, list->list_name));
        free(list->entries);
        free(list);
    }
}

/* TODO: Access classifier list routines via ofproto extension
         instead of directly through ofproto_class */
int
call_ofproto_ops_cls_apply(struct acl                     *acl,
                           struct port                    *bridgec_port,
                           struct ops_cls_interface_info  *interface_info,
                           enum ops_cls_direction         direction,
                           struct ops_cls_pd_status       *pd_status)
{
    struct ofproto *ofproto = get_bridge_ofproto(bridgec_port->bridge);
    int rc;
    rc = ofproto->ofproto_class->ops_cls_apply ?
        ofproto->ofproto_class->ops_cls_apply(acl->want_pi,
                                              ofproto,
                                              bridgec_port,
                                              interface_info,
                                              direction,
                                              pd_status) :
        EOPNOTSUPP;
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_remove(struct acl                       *acl,
                            struct port                      *bridgec_port,
                            struct ops_cls_interface_info    *interface_info,
                            enum ops_cls_direction           direction,
                            struct ops_cls_pd_status         *pd_status)
{
    struct ofproto *ofproto = get_bridge_ofproto(bridgec_port->bridge);
    int rc;
    rc = ofproto->ofproto_class->ops_cls_remove ?
        ofproto->ofproto_class->ops_cls_remove(&acl->uuid,
                                               acl->name,
                                               acl->type,
                                               ofproto,
                                               bridgec_port,
                                               interface_info,
                                               direction,
                                               pd_status) :
        EOPNOTSUPP;
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_replace(struct acl                      *orig_acl,
                             struct acl                      *new_acl,
                             struct port                     *bridgec_port,
                             struct ops_cls_interface_info   *interface_info,
                             enum ops_cls_direction          direction,
                             struct ops_cls_pd_status        *pd_status)
{
    struct ofproto *ofproto = get_bridge_ofproto(bridgec_port->bridge);
    int rc;
    rc = ofproto->ofproto_class->ops_cls_replace ?
        ofproto->ofproto_class->ops_cls_replace(&orig_acl->uuid,
                                                orig_acl->name,
                                                new_acl->want_pi,
                                                ofproto,
                                                bridgec_port,
                                                interface_info,
                                                direction,
                                                pd_status) :
        EOPNOTSUPP;
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_list_update(struct acl                     *acl,
                                 struct ops_cls_pd_list_status    *status)
{
    const struct ofproto_class *ofproto_class =
        get_bridge_provider_ofproto_class();
    int rc;
    rc = ofproto_class->ops_cls_list_update ?
        ofproto_class->ops_cls_list_update(acl->want_pi, status) :
        EOPNOTSUPP;
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_statistics_get(struct acl                     *acl,
                                    struct port                    *bridgec_port,
                                    struct ops_cls_interface_info  *interface_info,
                                    enum ops_cls_direction         direction,
                                    struct ops_cls_statistics      *statistics,
                                    int                            num_entries,
                                    struct ops_cls_pd_list_status  *status)
{
    struct ofproto *ofproto = get_bridge_ofproto(bridgec_port->bridge);
    int rc;
    rc = ofproto->ofproto_class->ops_cls_statistics_get ?
        ofproto->ofproto_class->ops_cls_statistics_get(
            &acl->uuid,
            acl->name,
            acl->type,
            ofproto,
            bridgec_port,
            interface_info,
            direction,
            statistics,
            num_entries,
            status) :
        EOPNOTSUPP;
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_statistics_clear(struct acl                     *acl,
                                      struct port                     *bridgec_port,
                                      struct ops_cls_interface_info   *interface_info,
                                      enum ops_cls_direction          direction,
                                      struct ops_cls_pd_list_status   *status)
{
    struct ofproto *ofproto = get_bridge_ofproto(bridgec_port->bridge);
    int rc;
    rc = ofproto->ofproto_class->ops_cls_statistics_clear ?
        ofproto->ofproto_class->ops_cls_statistics_clear(
            &acl->uuid,
            acl->name,
            acl->type,
            ofproto,
            bridgec_port,
            interface_info,
            direction,
            status) :
        EOPNOTSUPP;
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_statistics_clear_all(struct ops_cls_pd_list_status    *status)
{
    const struct ofproto_class *ofproto_class =
        get_bridge_provider_ofproto_class();
    int rc;
    rc = ofproto_class->ops_cls_statistics_clear_all ?
        ofproto_class->ops_cls_statistics_clear_all(status) :
        EOPNOTSUPP;
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}
