---
title: "Remote Process Instantiation via DCOM and PowerShell Script Block"
excerpt: "Remote Services, Distributed Component Object Model"
categories:
  - Endpoint
last_modified_at: 2021-11-15
toc: true
toc_label: ""
tags:
  - Remote Services
  - Lateral Movement
  - Distributed Component Object Model
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of PowerShell with arguments utilized to start a process on a remote endpoint by abusing the DCOM protocol. Specifically, this search looks for the abuse of ShellExecute and ExecuteShellCommand. Red Teams and adversaries alike may abuse DCOM for lateral movement and remote code execution.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-11-15
- **Author**: Mauricio Velazco, Splunk
- **ID**: fa1c3040-4680-11ec-a618-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | Distributed Component Object Model | Lateral Movement |

#### Search

```
`powershell` EventCode=4104 (Message="*Document.Application.ShellExecute*" OR Message="*Document.ActiveView.ExecuteShellCommand*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `remote_process_instantiation_via_dcom_and_powershell_script_block_filter`
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
Administrators may leverage DCOM to start a process on remote systems, but this activity is usually limited to a small set of hosts or users.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 90 | 70 | A process was started on a remote endpoint from $ComputerName by abusing WMI using PowerShell.exe |




#### Reference

* [https://attack.mitre.org/techniques/T1021/003/](https://attack.mitre.org/techniques/T1021/003/)
* [https://www.cybereason.com/blog/dcom-lateral-movement-techniques](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/lateral_movement/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/lateral_movement/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/remote_process_instantiation_via_dcom_and_powershell_script_block.yml) \| *version*: **1**