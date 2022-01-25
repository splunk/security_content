---
title: "Powershell Windows Defender Exclusion Commands"
excerpt: "Disable or Modify Tools, Impair Defenses"
categories:
  - Endpoint
last_modified_at: 2021-11-25
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Defense Evasion
  - Impair Defenses
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will detect a suspicious process commandline related to windows defender exclusion feature. This command is abused by adversaries, malware author and red teams to bypassed Windows Defender Anti-Virus product by excluding  folder path, file path, process, extensions and etc. from its real time or schedule scan to execute their malicious code. This is a good indicator for defense evasion and to look further for events after this behavior.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-25
- **Author**: Teoderick Contreras, Splunk
- **ID**: 907ac95c-4dd9-11ec-ba2c-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```
`powershell` EventCode=4104 (Message = "*Add-MpPreference *" OR Message = "*Set-MpPreference *") AND Message = "*-exclusion*" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `powershell_windows_defender_exclusion_commands_filter`
```

#### Associated Analytic Story
* [Remcos](/stories/remcos)
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [WhisperGate](/stories/whispergate)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### Kill Chain Phase
* Exploitation


#### Known False Positives
admin or user may choose to use this windows features.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | exclusion command $Message$ executed on $ComputerName$ |




#### Reference

* [https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html](https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html)
* [https://app.any.run/tasks/cf1245de-06a7-4366-8209-8e3006f2bfe5/](https://app.any.run/tasks/cf1245de-06a7-4366-8209-8e3006f2bfe5/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/defender_exclusion_powershell/powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/defender_exclusion_powershell/powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_windows_defender_exclusion_commands.yml) \| *version*: **1**