---
title: "Start Up During Safe Mode Boot"
excerpt: "Registry Run Keys / Startup Folder, Boot or Logon Autostart Execution"
categories:
  - Endpoint
last_modified_at: 2021-06-10
toc: true
toc_label: ""
tags:
  - Registry Run Keys / Startup Folder
  - Persistence
  - Privilege Escalation
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a modification or registry add to the safeboot registry as an autostart mechanism. This technique was seen in some ransomware to automatically execute its code upon a safe mode boot.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-10
- **Author**: Teoderick Contreras, Splunk
- **ID**: c6149154-c9d8-11eb-9da7-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path="*\\System\\CurrentControlSet\\Control\\SafeBoot\\Minimal\*" by Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `start_up_during_safe_mode_boot_filter`
```

#### Associated Analytic Story
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest


#### Kill Chain Phase
* Exploitation


#### Known False Positives
updated windows application needed in safe boot may used this registry


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | Safeboot registry $registry_path$ was added or modified with a new value $registry_value_name$ on $dest$ |




#### Reference

* [https://malware.news/t/threat-analysis-unit-tau-threat-intelligence-notification-snatch-ransomware/36365](https://malware.news/t/threat-analysis-unit-tau-threat-intelligence-notification-snatch-ransomware/36365)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/start_up_during_safe_mode_boot.yml) \| *version*: **1**