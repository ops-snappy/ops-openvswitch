"""Copyright (C) 2015 Hewlett Packard Enterprise Development LP
All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

import switch.CLI
topoDict = {"topoExecution": 1000,
            "topoTarget": "dut01 wrkston01",
            "topoDevices": "dut01 wrkston01",
            "topoLinks": "lnk01:dut01:wrkston01",
            "topoFilters": "dut01:system-category:switch,wrkston01:system-category:workstation"}

TEST_DESCRIPTION = "Virtual Topology / Physical Topology Sample Test"
tcInstance.tcInfo(tcName = ResultsDirectory['testcaseName'], tcDesc = TEST_DESCRIPTION)

tcInstance.defineStep(stepDesc="Connect to device "+ headers.topo['dut01'])
tcInstance.defineStep(stepDesc="Connect to device "+ headers.topo['wrkston01'])
tcInstance.defineStep(stepDesc="Set IP to workstation "+ headers.topo['wrkston01'])
tcInstance.defineStep(stepDesc="Set IP to switch "+ headers.topo['dut01'])
tcInstance.defineStep(stepDesc="Ping switch from workstation "+ headers.topo['wrkston01'] )


# Connecting the switch
tcInstance.startStep()
dut01_conn = switch.Connect(headers.topo['dut01'])
if dut01_conn is None:
   common.LogOutput('error', "Failed to connect to dut01")
   tcInstance.setVerdictAction (TC_STEPVERDICT_FAIL, TC_STEPFAILACTION_EXIT)
tcInstance.endStep()


# Connecting the workstation/

# Grab the name of the switch from the eTree
tcInstance.startStep()
hostElement = common.XmlGetElementsByTag(headers.TOPOLOGY, ".//device/system[category='workstation']/name", allElements=True)
numHosts = len(hostElement)
for hostE in hostElement:
   hName = hostE.text
   # Connect to the device
   common.LogOutput('info', "\nConnecting to the workstation " + hName)
   devConn = host.Connect(hName)
   if devConn is None:
      common.LogOutput('error', "\nFailed to connect to workstation " + hName)
      continue
tcInstance.endStep()

# Configuring IP on the workstation ethernet interface
tcInstance.startStep()
ipAddr = "192.168.20.101"
common.LogOutput('info', "\nConfiguring workstation IP" + hName)
retCode = host.ConfigNetwork(connection=devConn, eth="eth1",ipAddr=ipAddr, netMask="255.255.255.0", gateway="192.168.20.102",clear=0)
if retCode:
   common.LogOutput('error', "\nFailed to configure IP %s on  workstation %s " %(ipAddr, hName))
else:
   common.LogOutput('info', "\nSucceeded in configuring IP  %s on workstation %s " %(ipAddr, hName))
tcInstance.endStep()

# Configuring the switch

tcInstance.startStep()
ipAddr_sw = "192.168.20.100"
# These two ovs-vsctl commands are temporary until this gets fixed in the software.
common.LogOutput('info', "\nSetting interface to admin up")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="ovs-vsctl set interface 1 user_config:'admin=up'")
retCode = devIntRetStruct.get('returnCode')
if retCode != 0:
   common.LogOutput('error', "\nFailed to admin up")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="ovs-vsctl set interface 1 pm_info:connector=SFP_RJ45 pm_info:connector_status=supported")

common.LogOutput('info', "\nEntering vtysh")
returnStructure = switch.CLI.EnterVtyshShell(connection = dut01_conn)
returnCode = common.ReturnJSONGetCode(json = returnStructure)
if returnCode != 0:
   common.LogOutput('error', "Failed to get vtysh prompt")
else:
    vtyshInfo = common.ReturnJSONGetData(json=returnStructure, dataElement='vtyshPrompt')
    common.LogOutput("debug","vtysh shell buffer: \n"+vtyshInfo)


common.LogOutput('info', "\nEntering configure terminal")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="configure terminal")
retCode = devIntRetStruct.get('returnCode')
if retCode != 0:
   common.LogOutput('error', "\nFailed to enter config mode")

common.LogOutput('info', "\nCreating vrf0")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="vrf vrf0")
retCode = devIntRetStruct.get('returnCode')
if retCode != 0:
   common.LogOutput('error', "\nFailed to create vrf0")


common.LogOutput('info', "\nAdding interface 1")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="interface 1")
retCode = devIntRetStruct.get('returnCode')
if retCode != 0:
   common.LogOutput('error', "\nFailed to add interface 1 ")

common.LogOutput('info', "\nAdding vrf0")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="vrf attach vrf0")
retCode = devIntRetStruct.get('returnCode')
if retCode != 0:
   common.LogOutput('error', "\nFailed to add vrf0 ")

common.LogOutput('info', "\nGiving an IP address")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="ip address 192.168.20.100/24")
retCode = devIntRetStruct.get('returnCode')
if retCode != 0:
   common.LogOutput('error', "\nFailed to add IP address")

command = "end"
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command=command)
returnCode = devIntRetStruct.get('returnCode')
if returnCode != 0:
   common.LogOutput('error', "Failed to end")

command = "exit"
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command=command)
returnCode = devIntRetStruct.get('returnCode')
if returnCode != 0:
   common.LogOutput('error', "Failed to exit")


tcInstance.endStep()

#Pinging the switch from the workstation
tcInstance.startStep()
common.LogOutput('info', "\nPinging switch from workstation")
retCode = host.PingDevice(connection=devConn, ipAddr=ipAddr_sw)
if retCode:
   common.LogOutput('error', "\nFailed to ping %s from host %s " %(ipAddr_sw, hName))
tcInstance.endStep()


#Delete the vrf
returnStructure = switch.CLI.EnterVtyshShell(connection = dut01_conn)
common.LogOutput('info', "\nDeleting all the configurations")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="configure terminal")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="no vrf vrf0")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="end")
devIntRetStruct = switch.DeviceInteract(connection=dut01_conn, command="exit")
