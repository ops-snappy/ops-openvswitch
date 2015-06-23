/* Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
 * Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
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

#include <config.h>
#include "vrf.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include "async-append.h"
#include "coverage.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "hmapx.h"
#include "list.h"
#include "netdev.h"
#include "poll-loop.h"
#include "seq.h"
#include "shash.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(vrf);

COVERAGE_DEFINE(vrf_reconfigure);

struct iface {
    /* These members are always valid.
     *
     * They are immutable: they never change between iface_create() and
     * iface_destroy(). */
    struct ovs_list port_elem;  /* Element in struct port's "ifaces" list. */
    struct hmap_node iface_node; /* In struct vrf's "iface_by_name" hmap. */
    struct port *port;          /* Containing port. */
    char *name;                 /* Host network device name. */
    struct netdev *netdev;      /* Network device. */
    uint64_t change_seq;

    /* These members are valid only within vrf_reconfigure(). */
    const char *type;           /* Usually same as cfg->type. */
    const struct ovsrec_interface *cfg;
};

struct net_address {
    struct hmap_node addr_node;
    char *address;
};

struct port {
    struct hmap_node port_node; /* Element in struct vrf's "ports" hmap. */
    char *ip_address;
    char *ip6_address;
    struct hmap secondary_ipaddr; /* List of secondary IP address*/
    struct hmap secondary_ip6addr; /*List of secondary IPv6 address*/
    struct vrf *vrf;
    char *name;

    const struct ovsrec_port *cfg;

    /* To accomodate more than 1 interface per port */
    struct ovs_list ifaces;    /* List of "struct iface"s. */
};

struct vrf {
    struct hmap_node node;      /* In 'all_vrfs'. */
    char *name;                 /* User-specified arbitrary name. */
    const struct ovsrec_vrf *cfg;
    /* VRF ports. */
    struct hmap ports;          /* "struct port"s indexed by name. */
    struct hmap iface_by_name;  /* "struct iface"s indexed by name. */
    /* Used during reconfiguration. */
    struct shash wanted_ports;
};

/* All vrfs, indexed by name. */
static struct hmap all_vrfs = HMAP_INITIALIZER(&all_vrfs);

/* OVSDB IDL used to obtain configuration. */
extern struct ovsdb_idl *idl;

/* Most recently processed IDL sequence number. */
static unsigned int idl_seqno;

static void add_del_vrfs(const struct ovsrec_open_vswitch *);
static struct vrf*
vrf_lookup(const char *name);
static void vrf_create(const struct ovsrec_vrf *);
static void vrf_destroy(struct vrf *);
static struct port*
port_lookup(const struct vrf *vrf, const char *name);
static struct port *
port_create (struct vrf *vrf, const struct ovsrec_port *port_cfg);
static void
port_destroy(struct port *port);
static bool
iface_create(struct vrf *vrf, const struct ovsrec_interface *iface_cfg,
             const struct ovsrec_port *port_cfg);
static void
iface_destroy(struct iface *iface);

static struct iface *
iface_lookup(const struct vrf *vrf, const char *name)
{
    struct iface *iface;

    HMAP_FOR_EACH_WITH_HASH (iface, iface_node, hash_string(name, 0),
                             &vrf->iface_by_name) {
        if (!strcmp(iface->name, name)) {
            return iface;
        }
    }

    return NULL;
}

static struct net_address *
ip_address_lookup (struct port *cfg, const char *address)
{
    struct net_address *addr;

    HMAP_FOR_EACH_WITH_HASH (addr, addr_node, hash_string(address, 0),
                             &cfg->secondary_ipaddr) {
        if (!strcmp(addr->address, address)) {
            return addr;
        }
    }

    return NULL;
}

static struct net_address *
ip6_address_lookup (struct port *cfg, const char *address)
{
    struct net_address *addr;

    HMAP_FOR_EACH_WITH_HASH (addr, addr_node, hash_string(address, 0),
                             &cfg->secondary_ip6addr) {
        if (!strcmp(addr->address, address)) {
            return addr;
        }
    }

    return NULL;
}

/* Configure port ipv4/ipv6 address */
static int
vrf_port_configure_ip(struct vrf *vrf, char *ip_address,
                      struct port *port)
{

    VLOG_DBG("vrf_port_configure_ip called for ip %s", ip_address);

    struct iface *iface = iface_lookup(vrf, port->name);
    if( ( iface == NULL ) || ( iface->netdev == NULL ) ) {
        VLOG_ERR("Invalid Interface");
        return 1;
    }

    /* Call Provider */
    if (!netdev_set_ip_address(iface->netdev, ip_address,
                               port->name)) {
        VLOG_INFO("VRF %s: configured IP address %s",
                  vrf->name, ip_address);

        return 0;
    }
    else {
        VLOG_ERR("ip command failed");
        return 1;
    }
}

/* Delete port ipv4/ipv6 address */
static int
vrf_port_delete_ip(struct vrf *vrf, char *ip_address,
                 struct port *port)
{

    VLOG_DBG("vrf_port_delete_ip called for ip=%s", ip_address);

    struct iface *iface = iface_lookup(vrf, port->name);
    if( ( iface == NULL ) || ( iface->netdev == NULL ) ) {
        VLOG_ERR("Invalid Interface");
        return 0;
    }

    /* Call Provider */
    if (!netdev_delete_ip_address(iface->netdev, ip_address,
                                  port->name)) {
        VLOG_INFO("VRF %s: deleted configured IP address %s",
                  vrf->name, ip_address);

        return 0;
    }
    else {
        VLOG_ERR("ip command failed");
        return 1;
    }
}

static void
vrf_port_update_secondary_ipv6_address(struct vrf *vrf, struct port *port,
                                       struct ovsrec_port *cfg)
{
    struct shash new_ip6_list;
    struct net_address *addr, *next;
    struct shash_node *addr_node;
    int i;

    shash_init(&new_ip6_list);

    /*
     * Collect the interested network addresses
     */
    for (i = 0; i < cfg->n_ip6_address_secondary; i++) {
        if(!shash_add_once(&new_ip6_list, cfg->ip6_address_secondary[i],
                           cfg->ip6_address_secondary[i])) {
            VLOG_WARN("Duplicate address in secondary list %s\n",
                      cfg->ip6_address_secondary[i]);
        }
    }

    /*
     * Parse the existing list of addresses and remove obsolete ones
     */
    HMAP_FOR_EACH_SAFE (addr, next, addr_node, &port->secondary_ip6addr) {
        if (!shash_find_data(&new_ip6_list, addr->address)) {
            hmap_remove(&port->secondary_ip6addr, &addr->addr_node);
            vrf_port_delete_ip(vrf, addr->address, port);
            free(addr->address);
            free(addr);
        }
    }

    /*
     * Add the newly added addresses to the list
     */
    SHASH_FOR_EACH (addr_node, &new_ip6_list) {
        struct net_address *addr;
        const char *address = addr_node->data;
        if(!ip6_address_lookup(port, address)) {
            /*
             * Add the new address to the list
             */
            addr = xzalloc(sizeof *addr);
            addr->address = xstrdup(address);
            hmap_insert(&port->secondary_ip6addr, &addr->addr_node,
                        hash_string(addr->address, 0));
            vrf_port_configure_ip(vrf, addr->address, port);
        }
    }
}

static void
vrf_port_update_secondary_ipv4_address(struct vrf *vrf, struct port *port,
                                       struct ovsrec_port *cfg)
{
    struct shash new_ip_list;
    struct net_address *addr, *next;
    struct shash_node *addr_node;
    int i;

    shash_init(&new_ip_list);

    /*
     * Collect the interested network addresses
     */
    for (i = 0; i < cfg->n_ip_address_secondary; i++) {
        if(!shash_add_once(&new_ip_list, cfg->ip_address_secondary[i],
                           cfg->ip_address_secondary[i])) {
            VLOG_WARN("Duplicate address in secondary list %s\n",
                      cfg->ip_address_secondary[i]);
        }
    }

    /*
     * Parse the existing list of addresses and remove obsolete ones
     */
    HMAP_FOR_EACH_SAFE (addr, next, addr_node, &port->secondary_ipaddr) {
        if (!shash_find_data(&new_ip_list, addr->address)) {
            hmap_remove(&port->secondary_ipaddr, &addr->addr_node);
            vrf_port_delete_ip(vrf, addr->address, port);
            free(addr->address);
            free(addr);
        }
    }

    /*
     * Add the newly added addresses to the list
     */
    SHASH_FOR_EACH (addr_node, &new_ip_list) {
        struct net_address *addr;
        const char *address = addr_node->data;
        if(!ip_address_lookup(port, address)) {
            /*
             * Add the new address to the list
             */
            addr = xzalloc(sizeof *addr);
            addr->address = xstrdup(address);
            hmap_insert(&port->secondary_ipaddr, &addr->addr_node,
                        hash_string(addr->address, 0));
            vrf_port_configure_ip(vrf, addr->address, port);
        }
    }
}

static void
vrf_port_configure(struct vrf *vrf, struct port *port,
                   struct ovsrec_port *port_cfg)
{
    const struct ovsdb_idl_column *column;

    /*
     * Configure primary network addresses
     */
    if (port_cfg->ip_address) {
        if (port->ip_address) {
            if (strcmp(port->ip_address, port_cfg->ip_address) != 0) {
                vrf_port_delete_ip(vrf, port->ip_address, port);
                free(port->ip_address);

                port->ip_address = xstrdup(port_cfg->ip_address);
                vrf_port_configure_ip(vrf, port->ip_address, port);
            }
        }
        else {
            port->ip_address = xstrdup(port_cfg->ip_address);
            vrf_port_configure_ip(vrf, port->ip_address, port);
        }
    }
    else {
        if (port->ip_address != NULL) {
            vrf_port_delete_ip(vrf, port->ip_address, port);
            free(port->ip_address);
            port->ip_address = NULL;
        }
    }

    if (port_cfg->ip6_address) {
        if (port->ip6_address) {
            if (strcmp(port->ip6_address, port_cfg->ip6_address) !=0) {
                vrf_port_delete_ip(vrf, port->ip6_address, port);
                free(port->ip6_address);

                port->ip6_address = xstrdup(port_cfg->ip6_address);
                vrf_port_configure_ip(vrf, port->ip6_address, port);
            }
        }
        else {
            port->ip6_address = xstrdup(port_cfg->ip6_address);
            vrf_port_configure_ip(vrf, port->ip6_address, port);
        }
    }
    else {
        if (port->ip6_address != NULL) {
            vrf_port_delete_ip(vrf, port->ip6_address, port);
            free(port->ip6_address);
            port->ip6_address = NULL;
        }
    }

    /*
     * Configure secondary network addresses
     */
    OVSREC_IDL_GET_COLUMN(column, port_cfg, "ip_address_secondary");
    if (column) {
        if (OVSREC_IDL_IS_COLUMN_MODIFIED(column, idl_seqno) ) {
            VLOG_DBG("ip_address_secondary modified");
            vrf_port_update_secondary_ipv4_address(vrf, port, port_cfg);
        }
    }

    OVSREC_IDL_GET_COLUMN(column, port_cfg, "ip6_address_secondary");
    if (column) {
        if (OVSREC_IDL_IS_COLUMN_MODIFIED(column, idl_seqno) ) {
            VLOG_INFO("ip6_address_secondary modified");
            vrf_port_update_secondary_ipv6_address(vrf, port, port_cfg);
        }
    }
}

/* Interface Functions */

static void
iface_refresh_netdev_status(struct iface *iface)
{
    struct smap smap;

    enum netdev_features current;
    enum netdev_features pause_staus;
    enum netdev_flags flags;
    const char *link_state;
    uint8_t mac[ETH_ADDR_LEN];
    int64_t bps = 0, mtu_64, link_resets = 0;
    int mtu, error;

    if (iface->change_seq == netdev_get_change_seq(iface->netdev)) {
        return;
    }

    iface->change_seq = netdev_get_change_seq(iface->netdev);

    smap_init(&smap);

    if (!netdev_get_status(iface->netdev, &smap)) {
        ovsrec_interface_set_status(iface->cfg, &smap);
    } else {
        ovsrec_interface_set_status(iface->cfg, NULL);
    }

    smap_destroy(&smap);

    /* admin_state */
    error = netdev_get_flags(iface->netdev, &flags);
    if (!error) {
        const char *state = (flags & NETDEV_UP) ?
                                OVSREC_INTERFACE_ADMIN_STATE_UP :
                                OVSREC_INTERFACE_ADMIN_STATE_DOWN;

        ovsrec_interface_set_admin_state(iface->cfg, state);
    } else {
        ovsrec_interface_set_admin_state(iface->cfg, NULL);
    }

    /* link_state */
    link_state = netdev_get_carrier(iface->netdev) ?
                    OVSREC_INTERFACE_LINK_STATE_UP :
                    OVSREC_INTERFACE_LINK_STATE_DOWN;
    ovsrec_interface_set_link_state(iface->cfg, link_state);

    link_resets = netdev_get_carrier_resets(iface->netdev);
    ovsrec_interface_set_link_resets(iface->cfg, &link_resets, 1);

    /* duplex, speed, pause */
    error = netdev_get_features(iface->netdev, &current, NULL, NULL, NULL);
    if (!error) {

        pause_staus = (current & (NETDEV_F_PAUSE | NETDEV_F_PAUSE_ASYM));
        if (!pause_staus) {
            ovsrec_interface_set_pause(iface->cfg, OVSREC_INTERFACE_PAUSE_NONE);
        } else if (pause_staus == NETDEV_F_PAUSE) {
            ovsrec_interface_set_pause(iface->cfg, OVSREC_INTERFACE_PAUSE_RXTX);
        } else if (pause_staus == NETDEV_F_PAUSE_ASYM) {
            ovsrec_interface_set_pause(iface->cfg, OVSREC_INTERFACE_PAUSE_TX);
        } else {
            ovsrec_interface_set_pause(iface->cfg, OVSREC_INTERFACE_PAUSE_RX);
        }

        bps = netdev_features_to_bps(current, 0);
        const char *duplex = netdev_features_is_full_duplex(current) ?
                                OVSREC_INTERFACE_DUPLEX_FULL :
                                OVSREC_INTERFACE_DUPLEX_HALF;
        ovsrec_interface_set_duplex(iface->cfg, duplex);
        ovsrec_interface_set_link_speed(iface->cfg, &bps, 1);

    } else {
            ovsrec_interface_set_duplex(iface->cfg, NULL);
            ovsrec_interface_set_link_speed(iface->cfg, &bps, 1);
            ovsrec_interface_set_pause(iface->cfg, NULL);
    }

    /* mtu */
    error = netdev_get_mtu(iface->netdev, &mtu);
    if (!error) {
        mtu_64 = mtu;
        ovsrec_interface_set_mtu(iface->cfg, &mtu_64, 1);
    } else {
        ovsrec_interface_set_mtu(iface->cfg, NULL, 0);
    }

    /* MAC addr in use */
    error = netdev_get_etheraddr(iface->netdev, mac);
    if (!error) {
        char mac_string[32];

        sprintf(mac_string, ETH_ADDR_FMT, ETH_ADDR_ARGS(mac));
        ovsrec_interface_set_mac_in_use(iface->cfg, mac_string);
    } else {
        ovsrec_interface_set_mac_in_use(iface->cfg, NULL);
    }
}

/* Configures 'netdev' based on the "hw_intf_config"
 * columns in 'iface_cfg'.
 * Returns 0 if successful, otherwise a positive errno value. */
static int
iface_set_netdev_hw_intf_config(const struct ovsrec_interface *iface_cfg,
                                struct netdev *netdev)
{
    return netdev_set_hw_intf_config(netdev, &(iface_cfg->hw_intf_config));
}

/* Opens a network device for 'if_cfg' and configures it. */
static int
iface_do_create(const struct vrf *vrf,
                const struct ovsrec_interface *iface_cfg,
                struct netdev **netdevp)
{
    struct netdev *netdev = NULL;
    int error;

    if (netdev_is_reserved_name(iface_cfg->name)) {
        VLOG_WARN("could not create interface %s, name is reserved",
                  iface_cfg->name);
        error = EINVAL;
        goto error;
    }

    error = netdev_open(iface_cfg->name, "system", &netdev);
    if (error) {
        VLOG_WARN("could not open network device %s (%s)",
                  iface_cfg->name, ovs_strerror(error));
        goto error;
    }

    VLOG_DBG("vrf %s: added interface %s", vrf->name, iface_cfg->name);
    error = netdev_set_hw_intf_info(netdev, &(iface_cfg->hw_intf_info));
    if (error) {
        goto error;
    }

    error = iface_set_netdev_hw_intf_config(iface_cfg, netdev);
    if (error) {
        goto error;
    }

    *netdevp = netdev;
    return 0;

error:
    *netdevp = NULL;
    netdev_close(netdev);
    return error;
    return 0;
}

/* Returns the correct network device type for interface 'iface' in vrf
 * 'vrf'. */
static const char *
iface_get_type(const struct ovsrec_interface *iface,
               const struct ovsrec_vrf *vrf)
{
    const char *type;

    /* The local port always has type "internal".  Other ports take
     * their type from the database and default to "system" if none is
     * specified. */
    if(!strcmp(iface->type, "internal")) {
        type = "internal";
    } else {
        type = iface->type[0] ? iface->type : "system";
    }

    return type;
}

static bool
iface_create(struct vrf *vrf, const struct ovsrec_interface *iface_cfg,
             const struct ovsrec_port *port_cfg)
{
    struct netdev *netdev;
    struct port *port;
    struct iface *iface;
    int error;

    /* Do the bits that can fail up front. */
    ovs_assert(!iface_lookup(vrf, iface_cfg->name));
    error = iface_do_create(vrf, iface_cfg, &netdev);
    if (error) {
        return false;
    }

    /* Get or create the port structure. */
    port = port_lookup(vrf, port_cfg->name);
    if (!port) {
        port = port_create(vrf, port_cfg);
    }

    /* Create the iface structure. */
    iface = xzalloc(sizeof *iface);
    list_push_back(&port->ifaces, &iface->port_elem);
    hmap_insert(&vrf->iface_by_name, &iface->iface_node,
                hash_string(iface_cfg->name, 0));
    iface->port = port;
    iface->name = xstrdup(iface_cfg->name);
    iface->netdev = netdev;
    iface->cfg = iface_cfg;
    iface->type = iface_get_type(iface_cfg, vrf->cfg);

    iface_refresh_netdev_status(iface);

    return true;
}

static void
iface_destroy(struct iface *iface)
{
    if (iface) {
        struct port *port = iface->port;
        struct vrf *vrf = port->vrf;

        hmap_remove(&vrf->iface_by_name, &iface->iface_node);

        netdev_remove(iface->netdev);

        free(iface->name);
        free(iface);
    }
}

/* Port Functions */

static struct port*
port_lookup(const struct vrf *vrf, const char *name)
{
    struct port *port;

    HMAP_FOR_EACH_WITH_HASH (port, port_node, hash_string(name, 0),
                             &vrf->ports) {
        if (!strcmp(port->name, name)) {
            return port;
        }
    }

    return NULL;
}

static void
port_destroy(struct port *port)
{
    if (port) {
        struct vrf *vrf = port->vrf;
        struct iface *iface, *next;
        struct net_address *addr, *next_addr;

        LIST_FOR_EACH_SAFE (iface, next, port_elem, &port->ifaces) {
            iface_destroy(iface);
        }

        if (port->ip_address) {
            free(port->ip_address);
        }
        if (port->ip6_address) {
            free(port->ip6_address);
        }

        HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node, &port->secondary_ipaddr) {
            free(addr->address);
            free(addr);
        }
        hmap_destroy(&port->secondary_ipaddr);

        HMAP_FOR_EACH_SAFE (addr, next_addr, addr_node, &port->secondary_ip6addr) {
            free(addr->address);
            free(addr);
        }
        hmap_destroy(&port->secondary_ip6addr);

        hmap_remove(&vrf->ports, &port->port_node);
        free(port->name);
        free(port);
    }
}

static struct port *
port_create (struct vrf *vrf, const struct ovsrec_port *port_cfg)
{
    struct port *port;

    port = xzalloc(sizeof *port);
    port->vrf = vrf;
    port->name = xstrdup(port_cfg->name);
    port->cfg = port_cfg;
    list_init(&port->ifaces);
    hmap_init(&port->secondary_ipaddr);
    hmap_init(&port->secondary_ip6addr);

    hmap_insert(&vrf->ports, &port->port_node, hash_string(port->name, 0));
    return port;
}

/* VRF Functions */
static void
add_del_vrfs(const struct ovsrec_open_vswitch *cfg)
{
    struct vrf *vrf, *next;
    struct shash new_vrf;
    size_t i;

    /* Collect new vrfs' names and types. */
    shash_init(&new_vrf);
    for (i = 0; i < cfg->n_vrfs; i++) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        const struct ovsrec_vrf *vrf_cfg = cfg->vrfs[i];

        if (strchr(vrf_cfg->name, '/')) {
            /* Prevent remote ovsdb-server users from accessing arbitrary
             * directories, e.g. consider a vrf named "../../../etc/". */
            VLOG_INFO("ignoring vrf with invalid name \"%s\"",
                         vrf_cfg->name);
            VLOG_WARN_RL(&rl, "ignoring vrf with invalid name \"%s\"",
                         vrf_cfg->name);
        } else if (!shash_add_once(&new_vrf, vrf_cfg->name, vrf_cfg)) {
            VLOG_INFO("vrf %s specified twice", vrf_cfg->name);
            VLOG_WARN_RL(&rl, "vrf %s specified twice", vrf_cfg->name);
        }
    }

    /* Delete the vrfs' that are deleted from the db */
    HMAP_FOR_EACH_SAFE (vrf, next, node, &all_vrfs) {
        vrf->cfg = shash_find_data(&new_vrf, vrf->name);
        if (!vrf->cfg) {
            vrf_destroy(vrf);
        }
    }

    /* Add new vrfs. */
    for (i = 0; i < cfg->n_vrfs; i++) {
        const struct ovsrec_vrf *vrf_cfg = cfg->vrfs[i];
        struct vrf *vrf = vrf_lookup(vrf_cfg->name);
        if (!vrf) {
            vrf_create(vrf_cfg);
        }
    }

    shash_destroy(&new_vrf);
}

static void
vrf_collect_wanted_ports(struct vrf *vrf,
                         struct shash *wanted_ports)
{
    size_t i;

    shash_init(wanted_ports);

    for (i = 0; i < vrf->cfg->n_ports; i++) {
        const char *name = vrf->cfg->ports[i]->name;
        if (!shash_add_once(wanted_ports, name, vrf->cfg->ports[i])) {
            VLOG_WARN("VRF %s: %s specified twice as VRF port",
                      vrf->name, name);
        }
    }
}

static void
vrf_del_ports(struct vrf *vrf, const struct shash *wanted_ports)
{
    struct shash_node *port_node;
    struct port *port, *next;

    HMAP_FOR_EACH_SAFE (port, next, port_node, &vrf->ports) {
        port->cfg = shash_find_data(wanted_ports, port->name);
        if (!port->cfg) {
            /* Port not present in the wanted_ports list. Destroy */
            port_destroy(port);
        }
    }
}

static void
vrf_add_port(struct vrf *vrf, const struct ovsrec_port *port_cfg)
{
    size_t i;

    for (i = 0; i < port_cfg->n_interfaces; i++) {
        const struct ovsrec_interface *iface_cfg = port_cfg->interfaces[i];
        struct iface *iface = iface_lookup(vrf, iface_cfg->name);

        if (!iface) {
            iface_create(vrf, iface_cfg, port_cfg);
        }
    }
}

static void
vrf_reconfigure_ports(struct vrf *vrf, const struct shash *wanted_ports)
{
    struct shash_node *port_node;

    SHASH_FOR_EACH (port_node, wanted_ports) {
        const struct ovsrec_port *port_cfg = port_node->data;
        struct port *port = port_lookup(vrf, port_cfg->name);
        if (!port) {
            VLOG_DBG("Creating new port %s vrf %s\n",port_cfg->name, vrf->name);
            vrf_add_port(vrf, port_cfg);

            /* TODO: Fix this, combine ifs and make it one reconf */
            port = port_lookup(vrf, port_cfg->name);
            vrf_port_configure(vrf, port, port_cfg);
            VLOG_DBG("Port has IP: %s vrf %s\n",port_cfg->ip_address,
                      vrf->name);
            /* port_add_network_address(port, port_cfg); */
        } else if (port && OVSREC_IDL_IS_ROW_MODIFIED(port_cfg, idl_seqno)) {
            /* Port table row modified */
            VLOG_DBG("Port modified IP: %s vrf %s\n",port_cfg->ip_address,
                     vrf->name);
            vrf_port_configure(vrf, port, port_cfg);
        }
    }
}

static void
vrf_reconfigure(const struct ovsrec_open_vswitch *ovs_cfg)
{
    struct vrf *vrf, *next_vrf;

    COVERAGE_INC(vrf_reconfigure);

    /* Update the all_vrfs structure with any add/delete to vrf entries
     * in the database. */
    add_del_vrfs(ovs_cfg);
    /* For each vrf in all_vrfs, update the port list */
    HMAP_FOR_EACH (vrf, node, &all_vrfs) {
        VLOG_DBG("in vrf %s to delete ports\n",vrf->name);
        vrf_collect_wanted_ports(vrf, &vrf->wanted_ports);
        vrf_del_ports(vrf, &vrf->wanted_ports);
    }
    /* For each vrfs' port list, configure them thru' netdev */
    HMAP_FOR_EACH (vrf, node, &all_vrfs) {
        VLOG_DBG("in vrf %s to reconfigure ports\n",vrf->name);
        vrf_reconfigure_ports(vrf, &vrf->wanted_ports);
        shash_destroy(&vrf->wanted_ports);
    }
}

static struct vrf*
vrf_lookup(const char *name)
{
    struct vrf *vrf;

    HMAP_FOR_EACH_WITH_HASH (vrf, node, hash_string(name, 0), &all_vrfs) {
        if (!strcmp(vrf->name, name)) {
            return vrf;
        }
    }
    return NULL;
}

static void
vrf_destroy(struct vrf *vrf)
{
    if (vrf) {
        /* Delete all the associated ports before destroying vrf */
        struct port *port, *next_port;

        HMAP_FOR_EACH_SAFE (port, next_port, port_node, &vrf->ports) {
            VLOG_DBG("Calling port_destroy");
            port_destroy(port);
        }
        hmap_remove(&all_vrfs, &vrf->node);
        hmap_destroy(&vrf->ports);
        hmap_destroy(&vrf->iface_by_name);
        free(vrf->name);
        free(vrf);
    }
}

static void
vrf_create(const struct ovsrec_vrf *vrf_cfg)
{
    VLOG_DBG("In vrf_create for vrf %s",vrf_cfg->name);
    struct vrf *vrf;

    ovs_assert(!vrf_lookup(vrf_cfg->name));
    vrf = xzalloc(sizeof *vrf);

    vrf->name = xstrdup(vrf_cfg->name);
    vrf->cfg = vrf_cfg;

    hmap_init(&vrf->ports);
    hmap_init(&vrf->iface_by_name);
    hmap_insert(&all_vrfs, &vrf->node, hash_string(vrf->name, 0));
}

static void
run_status_update(void)
{
    struct vrf *vrf;
    struct iface *iface;

    HMAP_FOR_EACH (vrf, node, &all_vrfs) {
        HMAP_FOR_EACH (iface, iface_node, &vrf->iface_by_name) {
            iface_refresh_netdev_status(iface);
        }
    }
}

/* Public functions. */
void
vrf_init(void)
{
    idl_seqno = ovsdb_idl_get_seqno(idl);
}

void
vrf_exit(void)
{
    struct vrf *vrf, *next_vrf;

    HMAP_FOR_EACH_SAFE (vrf, next_vrf, node, &all_vrfs) {
        vrf_destroy(vrf);
    }
}

void
vrf_wait(void)
{
    VLOG_DBG("vrf_wait called\n");
}

void
vrf_run(void)
{
    static struct ovsrec_open_vswitch null_cfg;
    const struct ovsrec_open_vswitch *cfg;
    struct ovsdb_idl_txn *txn;
    VLOG_DBG("vrf_run called idl_seq %d\n",idl_seqno);

    if (!ovsdb_idl_has_lock(idl)) {
        VLOG_DBG("idl lock not present\n");
        return;
    }

    cfg = ovsrec_open_vswitch_first(idl);

    txn = ovsdb_idl_txn_create(idl);

    if (ovsdb_idl_get_seqno(idl) != idl_seqno) {
        vrf_reconfigure(cfg ? cfg : &null_cfg);
        idl_seqno = ovsdb_idl_get_seqno(idl);
    }
    run_status_update();

    /* TODO: Handle txn failure and retry */
    ovsdb_idl_txn_commit(txn);
    ovsdb_idl_txn_destroy(txn);
}
