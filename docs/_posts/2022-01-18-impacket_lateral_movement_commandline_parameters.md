---
title: "Impacket Lateral Movement Commandline Parameters"
excerpt: "Remote Services, SMB/Windows Admin Shares, Distributed Component Object Model, Windows Management Instrumentation, Windows Service"
categories:
  - Endpoint
last_modified_at: 2022-01-18
toc: true
toc_label: ""
tags:
  - Remote Services
  - Lateral Movement
  - SMB/Windows Admin Shares
  - Lateral Movement
  - Distributed Component Object Model
  - Lateral Movement
  - Windows Management Instrumentation
  - Execution
  - Windows Service
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for the presence of suspicious commandline parameters typically present when using Impacket tools. Impacket is a collection of python classes meant to be used with Microsoft network protocols. There are multiple scripts that leverage impacket libraries like `wmiexec.py`, `smbexec.py`, `dcomexec.py` and `atexec.py` used to execute commands on remote endpoints. By default, these scripts leverage administrative shares and hardcoded parameters that can be used as a signature to detect its use. Red Teams and adversaries alike may leverage Impackets tools for lateral movement and remote code execution.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-18
- **Author**: Mauricio Velazco, Splunk
- **ID**: 8ce07472-496f-11ec-ab3b-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement |

| [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | Distributed Component Object Model | Lateral Movement |

| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |

| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process = "*/c* \\\\127.0.0.1\\*" OR Processes.process= "*/c* 2>&1") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `impacket_lateral_movement_commandline_parameters_filter`
```

#### Associated Analytic Story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)
* [WhisperGate](/stories/whispergate)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
Although uncommon, Administrators may leverage Impackets tools to start a process on remote systems for system administration or automation use cases.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 90 | 70 | Suspicious command line parameters on $dest may represent a lateral movement attack with Impackets tools |




#### Reference

* [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)
* [https://attack.mitre.org/techniques/T1021/003/](https://attack.mitre.org/techniques/T1021/003/)
* [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)
* [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)
* [https://attack.mitre.org/techniques/T1053/005](https://attack.mitre.org/techniques/T1053/005)
* [https://github.com/SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)
* [https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/](https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/impacket/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/impacket/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/impacket_lateral_movement_commandline_parameters.yml) \| *version*: **2**