---
title: "NET Profiler UAC bypass"
excerpt: "Bypass User Account Control, Abuse Elevation Control Mechanism"
categories:
  - Endpoint
last_modified_at: 2021-07-12
toc: true
toc_label: ""
tags:
  - Bypass User Account Control
  - Privilege Escalation
  - Defense Evasion
  - Abuse Elevation Control Mechanism
  - Privilege Escalation
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect modification of registry to bypass UAC windows feature. This technique is to add a payload dll path on .NET COR file path that will be loaded by mmc.exe as soon it was executed. This detection rely on monitoring the registry key and values in the detection area. It may happened that windows update some dll related to mmc.exe and add dll path in this registry. In this case filtering is needed.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0252ca80-e30d-11eb-8aa3-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Privilege Escalation, Defense Evasion |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path= "*\\Environment\\COR_PROFILER_PATH" Registry.registry_value_name = "*.dll" by Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `net_profiler_uac_bypass_filter`
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest


#### Kill Chain Phase
* Exploitation


#### Known False Positives
limited false positive. It may trigger by some windows update that will modify this registry.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | Suspicious modification of registry $registry_path$ with possible payload path $registry_value_name$ in $dest$ |




#### Reference

* [https://offsec.almond.consulting/UAC-bypass-dotnet.html](https://offsec.almond.consulting/UAC-bypass-dotnet.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon2.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon2.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/net_profiler_uac_bypass.yml) \| *version*: **1**