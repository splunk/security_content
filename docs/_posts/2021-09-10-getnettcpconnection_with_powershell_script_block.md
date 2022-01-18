---
title: "GetNetTcpconnection with PowerShell Script Block"
excerpt: "System Network Connections Discovery"
categories:
  - Endpoint
last_modified_at: 2021-09-10
toc: true
toc_label: ""
tags:
  - System Network Connections Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get-NetTcpconnection ` commandlet. This commandlet is used to return a listing of network connections on a compromised system. Red Teams and adversaries alike may use this commandlet for situational awareness and Active Directory Discovery.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-10
- **Author**: Mauricio Velazco, Splunk
- **ID**: 091712ff-b02a-4d43-82ed-34765515d95d


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1049](https://attack.mitre.org/techniques/T1049/) | System Network Connections Discovery | Discovery |

#### Search

```
`powershell` EventCode=4104 (Message = "*Get-NetTcpconnection*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `getnettcpconnection_with_powershell_script_block_filter`
```

#### Associated Analytic Story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
Administrators or power users may use this PowerShell commandlet for troubleshooting.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | Network Connection discovery on $dest$ by $user$ |




#### Reference

* [https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/)
* [https://docs.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2019-ps](https://docs.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2019-ps)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1049/AD_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1049/AD_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/getnettcpconnection_with_powershell_script_block.yml) \| *version*: **1**