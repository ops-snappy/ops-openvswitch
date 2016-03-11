# Copyright (C) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
# Copyright (C) 2015, 2016 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if OPS
ovspluginslibincludedir = $(includedir)/ovs
ovspluginslibinclude_HEADERS = \
    plugins/plugins.h \
    plugins/plugin-extensions.h \
    plugins/reconfigure-blocks.h \
    plugins/asic-plugin.h

lib_LTLIBRARIES += plugins/libplugins.la
plugins_libplugins_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -Wl,--version-script=$(top_builddir)/plugins/libplugins.sym \
        $(AM_LDFLAGS)

plugins_libplugins_la_LIBADD = $(YAML_LIBS)

plugins_libplugins_la_SOURCES = \
    plugins/plugins.c \
    plugins/plugins.h \
    plugins/plugins_yaml.c \
    plugins/plugins_yaml.h \
    plugins/plugin-extensions.c \
    plugins/plugin-extensions.h \
    plugins/reconfigure-blocks.c \
    plugins/reconfigure-blocks.h \
    plugins/asic-plugin.h

plugins_libplugins_la_CFLAGS = -DYAML_PATH=$(sysconfdir)/openswitch/platform

plugins_libplugins_la_CPPFLAGS = $(AM_CPPFLAGS)
plugins_libplugins_la_CFLAGS += $(AM_CFLAGS)

pkgconfig_DATA += \
    $(srcdir)/plugins/libplugins.pc
endif
