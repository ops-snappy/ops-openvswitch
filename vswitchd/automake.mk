if OPS
sbin_PROGRAMS += vswitchd/ops-switchd
else
sbin_PROGRAMS += vswitchd/ovs-vswitchd
endif
man_MANS += vswitchd/ovs-vswitchd.8
DISTCLEANFILES += \
	vswitchd/ovs-vswitchd.8

if OPS
acl_includedir = $(includedir)/ovs/vswitchd/plugins/ops-classifier/include
acl_include_HEADERS = \
	vswitchd/plugins/ops-classifier/include/ofproto-ops-classifier.h

vswitchd_ops_switchd_SOURCES = \
	vswitchd/bridge.c \
	vswitchd/bridge.h \
	vswitchd/ovs-vswitchd.c \
	vswitchd/subsystem.c \
	vswitchd/system-stats.c \
	vswitchd/system-stats.h \
	vswitchd/xenserver.c \
	vswitchd/xenserver.h \
	vswitchd/bufmon.c \
	vswitchd/vrf.c \
	vswitchd/vrf.h \
	vswitchd/plugins/ops-classifier/include/ops-classifier.h \
	vswitchd/plugins/ops-classifier/include/ofproto-ops-classifier.h \
	vswitchd/plugins/ops-classifier/src/acl.c \
	vswitchd/plugins/ops-classifier/src/acl.h \
	vswitchd/plugins/ops-classifier/src/acl_parse.c \
	vswitchd/plugins/ops-classifier/src/acl_parse.h \
	vswitchd/plugins/ops-classifier/src/acl_port.c \
	vswitchd/plugins/ops-classifier/src/acl_port.h \
	vswitchd/plugins/ops-classifier/src/ofproto_helps.c \
	vswitchd/plugins/ops-classifier/src/ofproto_helps.h \
	vswitchd/plugins/ops-classifier/src/ops-classifier.c \
	vswitchd/plugins/ops-classifier/src/p2acl.c \
	vswitchd/plugins/ops-classifier/src/p2acl.h \
	vswitchd/plugins/ops-classifier/src/p2acl_colgrp.c \
	vswitchd/plugins/ops-classifier/src/p2acl_colgrp.h

vswitchd_ops_switchd_LDADD = \
	lib/libovscommon.la \
	ovsdb/libovsdb.la \
	ofproto/libofproto.la \
	lib/libsflow.la \
	lib/libopenvswitch.la \
	plugins/libplugins.la

vswitchd_ops_switchd_LDFLAGS = $(AM_LDFLAGS) $(DPDK_vswitchd_LDFLAGS)
else
vswitchd_ovs_vswitchd_SOURCES = \
	vswitchd/bridge.c \
	vswitchd/bridge.h \
	vswitchd/ovs-vswitchd.c \
	vswitchd/subsystem.c \
	vswitchd/system-stats.c \
	vswitchd/system-stats.h \
	vswitchd/xenserver.c \
	vswitchd/xenserver.h

vswitchd_ovs_vswitchd_LDADD = \
	lib/libovscommon.la \
	ovsdb/libovsdb.la \
	ofproto/libofproto.la \
	lib/libsflow.la \
	lib/libopenvswitch.la

vswitchd_ovs_vswitchd_LDFLAGS = $(AM_LDFLAGS) $(DPDK_vswitchd_LDFLAGS)
endif

EXTRA_DIST += vswitchd/INTERNALS
MAN_ROOTS += vswitchd/ovs-vswitchd.8.in

# vswitch schema and IDL
EXTRA_DIST += vswitchd/vswitch.ovsschema
pkgdata_DATA += vswitchd/vswitch.ovsschema vswitchd/configdb.ovsschema vswitchd/dhcp_leases.ovsschema

# vswitch E-R diagram
#
# If "python" or "dot" is not available, then we do not add graphical diagram
# to the documentation.
if HAVE_PYTHON
if HAVE_DOT
vswitchd/vswitch.gv: ovsdb/ovsdb-dot.in vswitchd/vswitch.ovsschema
	$(AM_V_GEN)$(OVSDB_DOT) --no-arrows $(srcdir)/vswitchd/vswitch.ovsschema > $@
vswitchd/vswitch.pic: vswitchd/vswitch.gv ovsdb/dot2pic
	$(AM_V_GEN)(dot -T plain < vswitchd/vswitch.gv | $(PERL) $(srcdir)/ovsdb/dot2pic -f 3) > $@.tmp && \
	mv $@.tmp $@
VSWITCH_PIC = vswitchd/vswitch.pic
VSWITCH_DOT_DIAGRAM_ARG = --er-diagram=$(VSWITCH_PIC)
DISTCLEANFILES += vswitchd/vswitch.gv vswitchd/vswitch.pic
endif
endif

# vswitch schema documentation
EXTRA_DIST += vswitchd/vswitch.xml
DISTCLEANFILES += vswitchd/ovs-vswitchd.conf.db.5
man_MANS += vswitchd/ovs-vswitchd.conf.db.5
vswitchd/ovs-vswitchd.conf.db.5: \
	ovsdb/ovsdb-doc vswitchd/vswitch.xml vswitchd/vswitch.ovsschema \
	$(VSWITCH_PIC)
	$(AM_V_GEN)$(OVSDB_DOC) \
		$(VSWITCH_DOT_DIAGRAM_ARG) \
		--version=$(VERSION) \
		$(srcdir)/vswitchd/vswitch.ovsschema \
		$(srcdir)/vswitchd/vswitch.xml > $@.tmp && \
	mv $@.tmp $@

# Version checking for vswitch.ovsschema.
ALL_LOCAL += vswitchd/vswitch.ovsschema.stamp
vswitchd/vswitch.ovsschema.stamp: vswitchd/vswitch.ovsschema
	@sum=`sed '/cksum/d' $? | cksum`; \
	expected=`sed -n 's/.*"cksum": "\(.*\)".*/\1/p' $?`; \
	if test "X$$sum" = "X$$expected"; then \
	  touch $@; \
	else \
	  ln=`sed -n '/"cksum":/=' $?`; \
	  echo >&2 "$?:$$ln: checksum \"$$sum\" does not match (you should probably update the version number and fix the checksum)"; \
	  exit 1; \
	fi
CLEANFILES += vswitchd/vswitch.ovsschema.stamp

# Clean up generated files from older OVS versions.  (This is important so that
# #include "vswitch-idl.h" doesn't get the wrong copy.)
CLEANFILES += vswitchd/vswitch-idl.c vswitchd/vswitch-idl.h
