---
title: "Windows Defender Exclusion Registry Entry"
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

This analytic will detect a suspicious process that modify a registry related to windows defender exclusion feature. This registry is abused by adversaries, malware author and red teams to bypassed Windows Defender Anti-Virus product by excluding folder path, file path, process, extensions and etc. from its real time or schedule scan to execute their malicious code. This is a good indicator for a defense evasion and to look further for events after this behavior.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-25
- **Author**: Teoderick Contreras, Splunk
- **ID**: 13395a44-4dd9-11ec-9df7-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path = "*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\*" by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `windows_defender_exclusion_registry_entry_filter`
```

#### Associated Analytic Story
* [Remcos](/stories/remcos)
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.user
* Registry.dest
* Registry.registry_value_name
* Registry.registry_value_data


#### Kill Chain Phase
* Exploitation


#### Known False Positives
admin or user may choose to use this windows features.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | exclusion registry $registry_path$  modified or added on $dest$ |




#### Reference

* [https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html](https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html)
* [https://app.any.run/tasks/cf1245de-06a7-4366-8209-8e3006f2bfe5/](https://app.any.run/tasks/cf1245de-06a7-4366-8209-8e3006f2bfe5/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/defender_exclusion_sysmon/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/defender_exclusion_sysmon/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_defender_exclusion_registry_entry.yml) \| *version*: **1**