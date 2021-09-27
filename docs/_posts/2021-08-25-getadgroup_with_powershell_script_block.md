---
title: "GetAdGroup with PowerShell Script Block"
excerpt: "Domain Groups"
categories:
  - Endpoint
last_modified_at: 2021-08-25
toc: true
tags:
  - Hunting
  - T1069.002
  - Domain Groups
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Reconnaissance
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get-AdGroup` commandlet. The `Get-AdGroup` commandlet is used to return a list of all domain groups. Red Teams and adversaries may leverage this commandlet to enumerate domain groups for situational awareness and Active Directory Discovery.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-25
- **Author**: Mauricio Velazco, Splunk
- **ID**: e4c73d68-794b-468d-b4d0-dac1772bbae7


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Domain Groups | Discovery |


#### Search

```
`powershell` EventCode=4104 (Message = "*Get-ADGroup*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `getadgroup_with_powershell_script_block_filter`
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
| 15.0 | 30 | 50 | Domain group discovery enumeration using PowerShell on $dest$ by $user$ |



#### Reference

* [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)
* [https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2019-ps](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2019-ps)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/getadgroup_with_powershell_script_block.yml) \| *version*: **1**