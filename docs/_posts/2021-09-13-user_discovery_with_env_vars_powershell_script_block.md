---
title: "User Discovery With Env Vars PowerShell Script Block"
excerpt: "System Owner/User Discovery
"
categories:
  - Endpoint
last_modified_at: 2021-09-13
toc: true
toc_label: ""
tags:
  - System Owner/User Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the use of PowerShell environment variables to identify the current logged user. Red Teams and adversaries may leverage this method to identify the logged user on a compromised endpoint for situational awareness and Active Directory Discovery.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-09-13
- **Author**: Mauricio Velazco, Splunk
- **ID**: 77f41d9e-b8be-47e3-ab35-5776f5ec1d20


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Discovery |

#### Search

```
`powershell` EventCode=4104 (Message = "*$env:UserName*" OR Message = "*[System.Environment]::UserName*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `user_discovery_with_env_vars_powershell_script_block_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `user_discovery_with_env_vars_powershell_script_block_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Path
* Message
* OpCode
* ComputerName
* User
* EventCode


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
Administrators or power users may use this PowerShell commandlet for troubleshooting.

#### Associated Analytic story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### Kill Chain Phase
* Reconnaissance



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | System user discovery on $dest$ |




#### Reference

* [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/AD_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/AD_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/user_discovery_with_env_vars_powershell_script_block.yml) \| *version*: **1**