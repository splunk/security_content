---
title: "Elevated Group Discovery with PowerView"
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

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get-DomainGroupMember` commandlet. `Get-DomainGroupMember` is part of PowerView, a PowerShell tool used to perform enumeration on Windows domains. As the name suggests, `Get-DomainGroupMember` is used to list the members of an specific domain group. Red Teams and adversaries alike use PowerView to enumerate elevated domain groups for situational awareness and Active Directory Discovery to identify high privileged users.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-25
- **Author**: Mauricio Velazco, Splunk
- **ID**: 10d62950-0de5-4199-a710-cff9ea79b413


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Domain Groups | Discovery |


#### Search

```
`powershell` EventCode=4104 (Message = "*Get-DomainGroupMember*") AND Message IN ("*Domain Admins*","*Enterprise Admins*", "*Schema Admins*", "*Account Operators*" , "*Server Operators*", "*Protected Users*",  "*Dns Admins*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `elevated_group_discovery_with_powerview_filter`
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
Administrators or power users may use this PowerView for troubleshooting.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 21.0 | 30 | 70 | Elevated group discovery using PowerView on $dest$ by $user$ |



#### Reference

* [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)
* [https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainGroupMember/](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainGroupMember/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/elevated_group_discovery_with_powerview.yml) \| *version*: **1**