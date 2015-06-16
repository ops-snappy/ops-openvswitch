#!/usr/bin/python

import os
import sys
import time
import pytest
import subprocess
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
    time.sleep(5)

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

    #Configure vrf and add port to it
    print('Configure a vrf vrf1 in DB.')
    s1.cmd("/usr/bin/ovs-vsctl add-vrf vrf1")
    print('Add a port 1 to vrf1')
    s1.cmd("/usr/bin/ovs-vsctl add-vrf-port vrf1 1");

    #Display port in vrf
    print('Expecting port 1 in vrf1"')
    output = s1.cmd("/usr/bin/ovs-vsctl list-vrf-ports vrf1")

    if '1' in output:
      print('Found port 1 in vrf1')
    else:
      print(output)
      assert 0, 'Failed to find port 1 in vrf1'

    #Display vrf to which port belongs
    print('Expecting vrf1 to which port 1 belongs')
    output = s1.cmd("/usr/bin/ovs-vsctl port-to-vrf 1")

    if 'vrf1' in output:
      print('Found vrf1 for port 1')
    else:
      print(output)
      assert 0, 'Failed to add  port 1 to vrf1'

    #Add a bridge and try to add
    #same port to bridge it should fail
    print('Configure a bridge br1 in DB')
    s1.cmd("/usr/bin/ovs-vsctl add-br br1")
    print('Try to add a port 1 to bridge')
    output = s1.cmd("/usr/bin/ovs-vsctl add-port br1 1");

    if 'constraint violation' in output:
      print('Success: Can\'t add port to bridge br1 as it belongs to vrf vrf1')
    else:
      print(output)
      assert 0, 'Failed: Port 1 added to br1 and already in vrf vrf1'

    #delete bridge
    s1.cmd("/usr/bin/ovs-vsctl del-br br1");

    #Delete port from vrf
    print('Remove port 1 from vrf1')
    s1.cmd("/usr/bin/ovs-vsctl del-vrf-port vrf1 1")
    output = s1.cmd("/usr/bin/ovs-vsctl list-vrf-ports vrf1")

    if '1' not in output:
      print('Success: Port 1 not in vrf1')
    else:
      print(output)
      assert 0, 'Failed: Port1 still found in vrf1'

    #Delete vrf
    s1.cmd("/usr/bin/ovs-vsctl del-vrf vrf1")
    print('=============================================')
    print('*** End of vrf-port commands ***')
    print('=============================================')

  # Extra cleanup if test fails in middle
  def vrf_cleanup(self):
    s1 = self.net.switches[ 0 ]
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

  # Vrf tests.
  def test_vrf_config_commands(self):
    self.test.vrf_config_commands()

  def test_vrf_port_config_commands(self):
    self.test.vrf_port_config_commands()

