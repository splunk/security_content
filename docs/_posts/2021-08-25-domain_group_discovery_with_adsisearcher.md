---
title: "Domain Group Discovery with Adsisearcher"
excerpt: "Permission Groups Discovery, Domain Groups"
categories:
  - Endpoint
last_modified_at: 2021-08-25
toc: true
toc_label: ""
tags:
  - Permission Groups Discovery
  - Discovery
  - Domain Groups
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the `[Adsisearcher]` type accelerator being used to query Active Directory for domain groups. Red Teams and adversaries may leverage `[Adsisearcher]` to enumerate domain groups for situational awareness and Active Directory Discovery.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-08-25
- **Author**: Mauricio Velazco, Splunk
- **ID**: 089c862f-5f83-49b5-b1c8-7e4ff66560c7


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1069](https://attack.mitre.org/techniques/T1069/) | Permission Groups Discovery | Discovery |

| [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Domain Groups | Discovery |

#### Search

```
`powershell` EventCode=4104 (Message = "*[adsisearcher]*" AND Message = "*(objectcategory=group)*" AND Message = "*findAll()*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `domain_group_discovery_with_adsisearcher_filter`
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
Administrators or power users may use Adsisearcher for troubleshooting.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 18.0 | 30 | 60 | Domain group discovery enumeration using PowerShell on $dest$ by $user$ |




#### Reference

* [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)
* [https://devblogs.microsoft.com/scripting/use-the-powershell-adsisearcher-type-accelerator-to-search-active-directory/](https://devblogs.microsoft.com/scripting/use-the-powershell-adsisearcher-type-accelerator-to-search-active-directory/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/domain_group_discovery_with_adsisearcher.yml) \| *version*: **1**