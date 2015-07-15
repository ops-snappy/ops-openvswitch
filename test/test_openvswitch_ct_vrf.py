#!/usr/bin/env python

# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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

from halonvsi.docker import *
from halonvsi.halon import *

class vrfTests( HalonTest ):

  def setupNet(self):
    # if you override this function, make sure to
    # either pass getNodeOpts() into hopts/sopts of the topology that
    # you build or into addHost/addSwitch calls
    self.net = Mininet(topo=SingleSwitchTopo(
      k=1,
      hopts=self.getHostOpts(),
      sopts=self.getSwitchOpts()),
      switch=HalonSwitch,
      host=HalonHost,
      link=HalonLink, controller=None,
      build=True)

  def vrf_config_commands(self):
    print('\n=========================================')
    print('*** Test to verify vrf commands ***')
    print('=========================================')
    #configuring Halon, in the future it would be through
    #proper Halon commands
    s1 = self.net.switches[ 0 ]

    #Configure vrf
    print('Configure a vrf vrf1 in DB')
    s1.cmd("/usr/bin/ovs-vsctl add-vrf vrf1")

    #Display vrf
    print('Expecting vrf1 in DB, command: "ovs-vsctl list-vrf"')
    output = s1.cmd("/usr/bin/ovs-vsctl list-vrf")

    if 'vrf1' in output:
      print('Found vrf1 in the DB')
    else:
      print(output)
      assert 0, 'Failed to find vrf1 in the DB'

    print('Expecting vrf1 in DB, command: "ovs-vsctl list VRF"')
    output = s1.cmd("/usr/bin/ovs-vsctl list VRF")

    if '_uuid' in output:
      print('Found vrf in DB')
    else:
      print(output)
      assert 0, ('Failed vrf in the DB')

    print('Expecting vrf1 in DB, command: "ovs-vsctl show"')
    output = s1.cmd("/usr/bin/ovs-vsctl show")

    if '"vrf1"' in output:
     print('Found vrf in DB')
    else:
      print(output)
      assert 0, 'Failed vrf in the DB'

    #Delete vrf
    print('Delete vrf1 in DB')
    s1.cmd("/usr/bin/ovs-vsctl del-vrf vrf1")
    output = s1.cmd("/usr/bin/ovs-vsctl list-vrf")

    if 'vrf1' not in output:
      print('vrf1 deleted in DB')
    else:
      print(output)
      assert 0, 'Failed to delete vrf in the DB'

    print('=============================================')
    print('*** End of vrf commands ***')
    print('=============================================')

  def vrf_port_config_commands(self):
    print('\n=============================================')
    print('*** Test to verify the vrf-port commands ***')
    print('=============================================')
    #configuring Halon, in the future it would be through
    #proper Halon commands
    s1 = self.net.switches[ 0 ]

    #Add port to default VRF
    print('Add a port 1 to vrf_default')
    s1.cmd("/usr/bin/ovs-vsctl add-vrf-port vrf_default 1");

    #Display port in vrf
    print('Expecting port 1 in vrf_default')
    output = s1.cmd("/usr/bin/ovs-vsctl list-vrf-ports vrf_default")

    if '1' in output:
      print('Found port 1 in vrf_default')
    else:
      print(output)
      assert 0, 'Failed to find port 1 in vrf_default'

    #Display vrf to which port belongs
    print('Expecting vrf_default to which port 1 belongs')
    output = s1.cmd("/usr/bin/ovs-vsctl port-to-vrf 1")

    if 'vrf_default' in output:
      print('Found vrf_default for port 1')
    else:
      print(output)
      assert 0, 'Failed to add port 1 to vrf_default'

    #Add a bridge and try to add
    #same port to bridge it should fail
    print('Configure a bridge br1 in DB')
    s1.cmd("/usr/bin/ovs-vsctl add-br br1")
    print('Try to add a port 1 to bridge')
    output = s1.cmd("/usr/bin/ovs-vsctl add-port br1 1");

    if 'constraint violation' in output:
      print('Success: Can\'t add port to bridge br1, belongs to vrf vrf_default')
    else:
      print(output)
      assert 0, 'Failed: Port 1 added to br1 and already in vrf vrf_default'

    #delete bridge
    s1.cmd("/usr/bin/ovs-vsctl del-br br1");

    #Delete port from vrf
    print('Remove port 1 from vrf_default')
    s1.cmd("/usr/bin/ovs-vsctl del-vrf-port vrf_default 1")
    output = s1.cmd("/usr/bin/ovs-vsctl list-vrf-ports vrf_default")

    if '1' not in output:
      print('Success: Port 1 not in vrf_default')
    else:
      print(output)
      assert 0, 'Failed: Port1 still found in vrf_default'

    print('=============================================')
    print('*** End of vrf-port commands ***')
    print('=============================================')

  def test_vrf_intf_ip_address(self):
    s1 = self.net.switches[ 0 ]

    print('\n=============================================')
    print('*** Test ip/ipv6 address on port ***')
    print('=============================================')
    s1.cmd("/usr/bin/ovs-vsctl add-vrf-port vrf_default 1")

    #Configure and check primary ip address
    print('Configure primary ip address 10.1.1.1/24 on port 1')
    s1.cmd("/usr/bin/ovs-vsctl set port 1 ip_address=10.1.1.1/24")
    output = s1.cmd("ip netns exec swns ip addr show dev 1 primary")
    if '10.1.1.1/24' in output:
      print('Primary address 10.1.1.1/24 configured on port 1')
    else:
      assert 0, 'Primary ip address configuration failed'

    #Configure and check secondary ip address
    print('Configure secondary ip address 10.1.1.2/24 on port 1')
    s1.cmd("/usr/bin/ovs-vsctl set port 1 ip_address_second=10.1.1.2/24")
    output = s1.cmd("ip netns exec swns ip addr show dev 1 secondary")
    if '10.1.1.2/24' in output:
      print('Secondary address 10.1.1.2/24 configured on port 1')
    else:
      assert 0, 'Secondary ip address configuration failed'

    #Configure and check ipv6 address
    print('Configure IPv6 address 2001::1/64 on port 1')
    s1.cmd("/usr/bin/ovs-vsctl set port 1 ip6_address='2001\:\:1/64'")
    output = s1.cmd("ip netns exec swns ip -6 addr show dev 1")
    if '2001::1/64' in output:
      print('IPv6 address 2001::1/64 configured on port 1')
    else:
      assert 0, 'IPv6 address configuration failed'

    #Delete ipv6 address
    print('Unconfigure IPv6 address 2001::1/64 on port 1')
    s1.cmd("/usr/bin/ovs-vsctl set port 1 ip6_address=[]")
    output = s1.cmd("ip netns exec swns ip -6 addr show dev 1")
    if '2001::1/64' not in output:
      print('IPv6 address 2001::1/64 unconfigured on port 1')
    else:
      assert 0, 'IPv6 address unconfiguration failed'

    #Delete ipv4 secondary address
    print('Unconfigure secondary ip address 10.1.1.2/24 on port 1')
    s1.cmd("/usr/bin/ovs-vsctl set port 1 ip_address_second=[]")
    output = s1.cmd("ip netns exec swns ip addr show dev 1 secondary")
    if '10.1.1.2/24' not in output:
      print('Secondary address 10.1.1.2/24 unconfigured on port 1')
    else:
      assert 0, 'Secondary ip address unconfiguration failed'

    #Delete ipv4 primary address
    print('Unconfigure primary ip address 10.1.1.1/24 on port 1')
    s1.cmd("/usr/bin/ovs-vsctl set port 1 ip_address=[]")
    output = s1.cmd("ip netns exec swns ip addr show dev 1 primary")
    if '10.1.1.1/24' not in output:
      print('Primary address 10.1.1.1/24 unconfigured on port 1')
    else:
      assert 0, 'Primary ip address unconfiguration failed'

    #Delete port from vrf and also remove vrf
    s1.cmd("/usr/bin/ovs-vsctl del-vrf-port vrf_default 1")

    print('=============================================')
    print('*** End of ip/ipv6 commands ***')
    print('=============================================')

  #Extra cleanup if test fails in middle
  def vrf_cleanup(self):
    s1 = self.net.switches[ 0 ]

    output = s1.cmd("ip netns exec swns ip addr show dev 1")
    if 'inet' in output:
      s1.cmd("ip netns exec swns ip address flush dev 1")

    output = s1.cmd("/usr/bin/ovs-vsctl list-vrf")
    if 'vrf1' in output:
      s1.cmd("/usr/bin/ovs-vsctl del-vrf vrf1")

    output = s1.cmd("/usr/bin/ovs-vsctl list-br")
    if 'br1' in output:
      s1.cmd("/usr/bin/ovs-vsctl del-br1 br1")


class Test_vrf:
  # Create the Mininet topology based on mininet.
  test = vrfTests()

  def setup(self):
    pass

  def teardown(self):
    pass

  def setup_class(cls):
    pass

  def teardown_class(cls):
    # Stop the Docker containers, and
    # mininet topology
    Test_vrf.test.net.stop()

  def setup_method(self, method):
    pass

  def teardown_method(self, method):
    self.test.vrf_cleanup()

  def __del__(self):
    del self.test

  # HALON_TODO: When multiple VRFs are supported, change the script accordingly.

  # Vrf tests.
  #def test_vrf_config_commands(self):
  #  self.test.vrf_config_commands()

  def test_vrf_port_config_commands(self):
    self.test.vrf_port_config_commands()

  def test_vrf_intf_ip_address(self):
    self.test.test_vrf_intf_ip_address()
