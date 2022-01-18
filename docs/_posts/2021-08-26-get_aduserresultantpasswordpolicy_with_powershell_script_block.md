---
title: "Get ADUserResultantPasswordPolicy with Powershell Script Block"
excerpt: "Password Policy Discovery"
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
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get-ADUserResultantPasswordPolicy` commandlet used to obtain the password policy in a Windows domain. Red Teams and adversaries alike may use PowerShell to enumerate domain policies for situational awareness and Active Directory Discovery.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-26
- **Author**: Teoderick Contreras, MAuricio Velazco, Splunk
- **ID**: 737e1eb0-065a-11ec-921a-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1201](https://attack.mitre.org/techniques/T1201/) | Password Policy Discovery | Discovery |

#### Search

```
`powershell` EventCode=4104 Message ="*Get-ADUserResultantPasswordPolicy*" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `get_aduserresultantpasswordpolicy_with_powershell_script_block_filter`
```

#### Associated Analytic Story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
The following Hunting analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
Administrators or power users may use this command for troubleshooting.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | powershell process having commandline $Message$ to query domain user password policy. |




#### Reference

* [https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
* [https://attack.mitre.org/techniques/T1201/](https://attack.mitre.org/techniques/T1201/)
* [https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduserresultantpasswordpolicy?view=windowsserver2019-ps](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduserresultantpasswordpolicy?view=windowsserver2019-ps)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/get_aduserresultantpasswordpolicy_with_powershell_script_block.yml) \| *version*: **1**