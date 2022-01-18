---
title: "GetWmiObject Ds Computer with PowerShell Script Block"
excerpt: "Remote System Discovery"
categories:
  - Endpoint
last_modified_at: 2021-09-01
toc: true
toc_label: ""
tags:
  - Remote System Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get-WmiObject` commandlet. The `DS_Computer` class parameter leverages WMI to query for all domain computers. Red Teams and adversaries may leverage this commandlet to enumerate domain computers for situational awareness and Active Directory Discovery.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-01
- **Author**: Mauricio Velazco, Splunk
- **ID**: 29b99201-723c-4118-847a-db2b3d3fb8ea


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery | Discovery |

#### Search

```
`powershell` EventCode=4104 (Message=*Get-WmiObject* AND Message=*"namespace root\\directory\\ldap"* AND Message=*"class ds_computer"*) 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `getwmiobject_ds_computer_with_powershell_script_block_filter`
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
| 15.0 | 30 | 50 | Remote system discovery enumeration on $dest$ by $user$ |




#### Reference

* [https://attack.mitre.org/techniques/T1018/](https://attack.mitre.org/techniques/T1018/)
* [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/AD_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/AD_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/getwmiobject_ds_computer_with_powershell_script_block.yml) \| *version*: **1**