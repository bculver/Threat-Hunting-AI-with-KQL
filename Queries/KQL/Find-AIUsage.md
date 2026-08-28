# Find-AIUsage

## Description
Find Cloud and Local AI agents inthe environment.

## KQL Query

DeviceNetworkEvents

''' kql
let ai_iocs = externaldata(site: dynamic)
   [h"https://github.com/bculver/Threat-Hunting-AI-with-KQL/Resources/AiToolsIOCList.csv"] with(format='csv')
;
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where ActionType =~ "connectionsuccess"
| extend RemoteUrl=tolower(replace_string(tostring(split(replace_regex(RemoteUrl,@"http(s)?://",""),"/")[0]),"www.",""))
| where RemoteUrl in (ai_iocs)
'''

DeviceProcessEvents

''' kql
DeviceProcessEvents

'''

DeviceFileEvents

''' kql
DeviceFileEvents

'''