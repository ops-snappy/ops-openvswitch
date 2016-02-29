#!/usr/bin/python

# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from opsvsi.docker import *
from opsvsi.opsvsitest import *
from opsvsiutils.systemutil import *


class socketFilePermissionTests(OpsVsiTest):

    def setupNet(self):
        # if you override this function, make sure to
        # either pass getNodeOpts() into hopts/sopts of the topology that
        # you build or into addHost/addSwitch calls
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        openswitch_topo = SingleSwitchTopo(
            k=0, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(openswitch_topo, switch=VsiOpenSwitch,
                           host=Host, link=OpsVsiLink,
                           controller=None, build=True)

    def socket_file_permission_verify(self):
        info("########## Verify DB socket file permissions ##########\n")
        # configuring OpenSwitch, in the future it would be through
        # proper OpenSwitch commands
        s1 = self.net.switches[0]

        # Check permissions of socket files present in /var/run/openvswitch
        output = s1.cmd("ls -l /var/run/openvswitch")
        lines = output.split('\n')
        for line in lines:
            if 'srwxrw' in line:
                if 'ovsdb-client' not in line:
                    info("Test failed!")
                    return

        info("########## File permissions and group are valid "
             "for socket files ##########\n")


class Test_socket_file_permissions:

    def setup_class(cls):
        Test_socket_file_permissions.test = socketFilePermissionTests()

    # Test for socket file permissions
    def test_socket_file_permission_verify(self):
        self.test.socket_file_permission_verify()

    def teardown_class(cls):
        # Stop the Docker containers, and
        # mininet topology
        Test_socket_file_permissions.test.net.stop()

    def __del__(self):
        del self.test
