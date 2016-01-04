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

#include "acl_port.h"
#include "vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "vswitchd/bridge.h"

VLOG_DEFINE_THIS_MODULE(ops_cls_acl_port);

/*************************************************************
 * acl_port search routines
 *************************************************************/
static struct hmap all_ports = HMAP_INITIALIZER(&all_ports);
static struct acl_port *
port_lookup(const struct uuid* uuid)
{
    struct acl_port *port;

    HMAP_FOR_EACH_WITH_HASH(port, all_node_uuid, uuid_hash(uuid),
                            &all_ports) {
        if (uuid_equals(&port->uuid, uuid)) {
            return port;
        }
    }
    return NULL;
}

/************************************************************
 * acl_port_new() and acl_port_delete() are low-level routines that
 * deal with PI acl_port data structures. They take care off all the
 * memorary management, hmap memberships, etc. They DO NOT make any PD
 * calls.
 ************************************************************/
static struct acl_port*
acl_port_new(const struct ovsrec_port *ovsdb_row, unsigned int seqno)
{
    struct acl_port *port = xzalloc(sizeof *port);
    port->uuid = ovsdb_row->header_.uuid;
    port->name = xstrdup(ovsdb_row->name); /* we can outlive ovsdb_row */

    /* setup my p2acls to know about me and which colgrp they represent */
    for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
        p2acl_construct(&port->p2acls[i], port, i);
    }

    port->ovsdb_row = ovsdb_row;
    port->delete_seqno = seqno;
    hmap_insert(&all_ports, &port->all_node_uuid, uuid_hash(&port->uuid));
    return port;
}

static void
acl_port_delete(struct acl_port* port)
{
    if (port) {
        hmap_remove(&all_ports, &port->all_node_uuid);
        free(CONST_CAST(char *, port->name));

        /* cleanup my p2acls */
        for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
            p2acl_destruct(&port->p2acls[i]);
        }

        free(port);
    }
}

/************************************************************
 * acl_port_cfg_create(), acl_port_cfg_update(), acl_port_delete() are
 * the PI acl CRUD routines.
 ************************************************************/
static void acl_port_cfg_update(struct acl_port* port);

static struct acl_port*
acl_port_cfg_create(const struct ovsrec_port *ovsdb_row, unsigned int seqno)
{
    VLOG_DBG("PORT %s created", ovsdb_row->name);

    struct acl_port *port = acl_port_new(ovsdb_row, seqno);

    /* TODO: rework this when we have the full
       Change/Transaction structure */
    /* Defer PD create to P2ACL structs */
    struct port* bridgec_port = global_port_lookup(port->name);
    /* The lookup shouldn't fail since our temporary code runs
       completely after the bridge.c code does all of it's Port
       manipulation.
    */
    ovs_assert(bridgec_port);

    for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
        p2acl_cfg_create(&port->p2acls[i], bridgec_port);
    }

    return port;
}

static void
acl_port_cfg_update(struct acl_port* port)
{
    VLOG_DBG("PORT %s changed", port->name);

    /* TODO: rework this when we have the full
       Change/Transaction structure */
    /* Defer PD update to P2ACL structs */
    struct port* bridgec_port = global_port_lookup(port->name);
    if (!bridgec_port) {
        VLOG_ERR("PORT %s not found", port->name);
        return;
    }
    for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
        p2acl_cfg_update(&port->p2acls[i], bridgec_port);
    }
}

static void
acl_port_cfg_delete(struct acl_port* port)
{
    VLOG_DBG("PORT %s deleted", port->name);

    /* TODO: rework this when we have the full
       Change/Transaction structure */
    /* Defer PD delete to P2ACL structs */
    struct port* bridgec_port = global_port_lookup(port->name);
    if (!bridgec_port) {
        VLOG_ERR("PORT %s not found", port->name);
        return;
    }
    for (int i = 0; i < NUM_P2ACL_COLGRPS; ++i) {
        p2acl_cfg_delete(&port->p2acls[i], bridgec_port);
    }

    /* There's nothing to log to OVSDB for an PORT:D */
    acl_port_delete(port);
}

/************************************************************
 * Top level routine to check if PORTs need to reconfigure
 ************************************************************/
void
acl_port_maybe_reconfigure(void)
{
    /* Quick check for PORT table changes */
    bool ports_created;
    bool ports_updated;
    bool ports_deleted;
    bool have_ports = !hmap_is_empty(&all_ports);
    const struct ovsrec_port *port_row = ovsrec_port_first(idl);
    if (port_row) {
        ports_created = OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(port_row, idl_seqno);
        ports_updated = OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(port_row, idl_seqno);

        /* We only care about ports_deleted if we already have some ports.
         * If this reconfigure is the result of an ovsdb reconnect, we have to
         * assume that records have been deleted while we were away. */
        ports_deleted = have_ports &&
            (ovsdb_reconnected ||
             OVSREC_IDL_ANY_TABLE_ROWS_DELETED(port_row, idl_seqno));
    } else {
        /* There are no PORT rows in OVSDB. */
        ports_created = false;
        ports_updated = false;
        ports_deleted = have_ports;
    }

    /* Check if we need to process any PORT:[CU]
     *   - PORT:C will show up as ports_created
     *   - PORT:U will show up as ports_updated
     * We also have to traverse if ports_deleted in order to mark/sweep.
     */
    if (ports_created || ports_updated || ports_deleted) {
        const struct ovsrec_port *port_row_next;
        OVSREC_PORT_FOR_EACH_SAFE(port_row, port_row_next, idl) {
            struct acl_port *port = port_lookup(&port_row->header_.uuid);
            if (!port) {
                (void) acl_port_cfg_create(port_row, idl_seqno);
            } else {
                /* Always update these, even if nothing else has changed,
                 * The ovsdb_row may have changed out from under us.
                 * delete_seqno is use as mark/sweep to delete unused ACLs.
                 */
                port->ovsdb_row = port_row;
                port->delete_seqno = idl_seqno;

                /* Check if this is an ACL:[CU] */
                bool row_changed =
                    (OVSREC_IDL_IS_ROW_MODIFIED(port_row, idl_seqno) ||
                     OVSREC_IDL_IS_ROW_INSERTED(port_row, idl_seqno));
                if (row_changed) {
                    /* TODO: This is actually too coarse for us.
                     *       The port row can change for all kinds of
                     *       reasons that we don't care about.
                     */
                    acl_port_cfg_update(port);
                }
            }
        }
    } else {
        VLOG_DBG("No changes in PORT table");
    }


    /* Detect any PORT:D by sweeping looking for old delete_seqno. */
    if (ports_deleted) {
        struct acl_port *port, *next_port;
        HMAP_FOR_EACH_SAFE (port, next_port, all_node_uuid, &all_ports) {
            if (port->delete_seqno < idl_seqno) {
                /* TODO: After we use Change objects, move the
                 *       PORT:D handling to before PORT:[CU] */
                acl_port_cfg_delete(port);
            }
        }
    }
}
