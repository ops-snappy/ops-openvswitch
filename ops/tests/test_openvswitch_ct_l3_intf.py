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

# test_openvswitch_ct_l3.py: Test to verify basic l3 in switch
"""
import re

topoDict = {"topoExecution": 1000,
            "topoTarget": "dut01",
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}

TEST_DESCRIPTION = "Test L3"
tcInstance.tcInfo(tcName = ResultsDirectory['testcaseName'], tcDesc = TEST_DESCRIPTION)

#Defining the Test Steps
tcInstance.defineStep(stepDesc="Connect to device "+ headers.topo['dut01'])
tcInstance.defineStep(stepDesc="Check the ip interface is enabled on switch "+ headers.topo['dut01'])

# Step 1 - connect to Switch
tcInstance.startStep()

dut01_conn = switch.Connect(headers.topo['dut01'])
if dut01_conn == None:
   # Means we had an issue in the connect logic
    common.LogOutput('error', "Failed to connect to device " + headers.topo['dut01'])
    assert 0, 'Failed to connect to switch'

#Waiting some time for the switch to come up
common.Sleep(seconds=25, message="Waiting for switch processes to fully come up")

#Check vrf
cmd = "/usr/bin/ovs-vsctl list-vrf"
retStruct = switch.DeviceInteract(connection=dut01_conn, command=cmd)
output = retStruct.get('buffer')
if 'vrf_default' not in output:
    assert 0, 'Failed to find vrf_default on dut01'
else:
    common.LogOutput('info', "vrf_default found on dut01\n")

#Add port 1 to vrf
common.LogOutput('info', "Add port 1 to vrf_default")
cmd = "/usr/bin/ovs-vsctl add-vrf-port vrf_default 1"
switch.DeviceInteract(connection=dut01_conn, command=cmd)

#Check for port
cmd = "/usr/bin/ovs-vsctl list-vrf-ports vrf_default"
retStruct = switch.DeviceInteract(connection=dut01_conn, command=cmd)
output = retStruct.get('buffer')
if 'vrf1' not in output:
    assert 0, 'Failed to configure port 1 on dut01'
else:
    common.LogOutput('info', "port 1 configured on dut01\n")

#Configure ip address on port 1
common.LogOutput('info', "Configure primary ip address 10.1.1.1/24 on port 1")
cmd = "/usr/bin/ovs-vsctl set port 1 ip_address=10.1.1.1/24"
switch.DeviceInteract(connection=dut01_conn, command=cmd)

#Check for ip address
cmd = "ip netns exec swns ip addr show dev 1 primary"
retStruct = switch.DeviceInteract(connection=dut01_conn, command=cmd)
output = retStruct.get('buffer')
if '10.1.1.1/24' not in output:
    assert 0, 'Primary ip address configuration failed'
else:
    common.LogOutput('info', "10.1.1.1 configured on port 1\n")

#Verify the port on line card is l3 enabled
common.LogOutput('info', "Verify port is l3 enabled by looking at mac address")
cmd = "/usr/bin/ovs-appctl plugin/debug l3intf"
retStruct = switch.DeviceInteract(connection=dut01_conn, command=cmd)
buf = retStruct.get('buffer')
output = re.search(r'([0-9A-F]{1,2}[:-]){5}([0-9A-F]{1,2})', buf, re.I).group()
if output:
    common.LogOutput('info', "port 1 l3 enabled\n")
else:
    assert 0, 'Failed to enable l3 on port 1'


#Clean up
common.LogOutput('info', "Test cleanup: delete port, vrf ...")
#Delete ip address
cmd = "/usr/bin/ovs-vsctl set port 1 ip_address=[]"
switch.DeviceInteract(connection=dut01_conn, command=cmd)

#Delete port
cmd = "/usr/bin/ovs-vsctl del-vrf-port vrf_default 1"
switch.DeviceInteract(connection=dut01_conn, command=cmd)

tcInstance.endStep()
"""
