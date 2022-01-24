---
title: "Interactive Session on Remote Endpoint with PowerShell"
excerpt: "Remote Services, Windows Remote Management"
categories:
  - Endpoint
last_modified_at: 2021-11-18
toc: true
toc_label: ""
tags:
  - Remote Services
  - Lateral Movement
  - Windows Remote Management
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the usage of the `Enter-PSSession`. This commandlet can be used to open an interactive session on a remote endpoint leveraging the WinRM protocol. Red Teams and adversaries alike may abuse WinRM and `Enter-PSSession` for lateral movement and remote code execution.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-11-18
- **Author**: Mauricio Velazco, Splunk
- **ID**: a4e8f3a4-48b2-11ec-bcfc-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management | Lateral Movement |

#### Search

```
powershell` EventCode=4104 (Message="*Enter-PSSession*" AND Message="*-ComputerName*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `interactive_session_on_remote_endpoint_with_powershell_filter`
```

#### Associated Analytic Story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup instructions can be found https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
Administrators may leverage WinRM and `Enter-PSSession` for administrative and troubleshooting tasks. This activity is usually limited to a small set of hosts or users. In certain environments, tuning may not be possible.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 90 | 50 | An interactive session was opened on a remote endpoint from $ComputerName |




#### Reference

* [https://attack.mitre.org/techniques/T1021/006/](https://attack.mitre.org/techniques/T1021/006/)
* [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement_pssession/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement_pssession/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/interactive_session_on_remote_endpoint_with_powershell.yml) \| *version*: **1**