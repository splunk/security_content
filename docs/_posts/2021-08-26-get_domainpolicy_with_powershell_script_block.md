---
title: "Get DomainPolicy with Powershell Script Block"
excerpt: "Password Policy Discovery
"
categories:
  - Endpoint
last_modified_at: 2021-08-26
toc: true
toc_label: ""
tags:
  - Password Policy Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get DomainPolicy` commandlet used to obtain the password policy in a Windows domain. Red Teams and adversaries alike may use PowerShell to enumerate domain policies for situational awareness and Active Directory Discovery.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-08-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: a360d2b2-065a-11ec-b0bf-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1201](https://attack.mitre.org/techniques/T1201/) | Password Policy Discovery | Discovery |

#### Search

```
`powershell` EventCode=4104 Message ="*Get-DomainPolicy*" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `get_domainpolicy_with_powershell_script_block_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `get_domainpolicy_with_powershell_script_block_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### How To Implement
The following Hunting analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Known False Positives
Administrators or power users may use this command for troubleshooting.

#### Associated Analytic story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### Kill Chain Phase
* Reconnaissance



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 50 | 60 | powershell process having commandline $Message$ to query domain policy. |




#### Reference

* [https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
* [https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainPolicy/](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainPolicy/)
* [https://attack.mitre.org/techniques/T1201/](https://attack.mitre.org/techniques/T1201/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/get_domainpolicy_with_powershell_script_block.yml) \| *version*: **1**