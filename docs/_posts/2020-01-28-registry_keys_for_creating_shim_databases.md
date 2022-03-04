---
title: "Registry Keys for Creating SHIM Databases"
excerpt: "Application Shimming
, Event Triggered Execution
"
categories:
  - Endpoint
last_modified_at: 2020-01-28
toc: true
toc_label: ""
tags:

  - Application Shimming
  - Event Triggered Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for registry activity associated with application compatibility shims, which can be leveraged by attackers for various nefarious purposes.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-01-28
- **Author**: Bhavin Patel, Patrick Bareiss, Teoderick Contreras, Splunk
- **ID**: f5f6af30-7aa7-4295-bfe9-07fe87c01bbb


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1546.011](https://attack.mitre.org/techniques/T1546/011/) | Application Shimming | Persistence, Privilege Escalation |

| [T1546](https://attack.mitre.org/techniques/T1546/) | Event Triggered Execution | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Registry where Registry.registry_path=*CurrentVersion\\AppCompatFlags\\Custom* OR Registry.registry_path=*CurrentVersion\\AppCompatFlags\\InstalledSDB* by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data 
| `registry_keys_for_creating_shim_databases_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `registry_keys_for_creating_shim_databases_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.dest
* Registry.user


#### How To Implement
To successfully implement this search, you must populate the Change_Analysis data model. This is typically populated via endpoint detection and response product, such as Carbon Black or other endpoint data sources such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Known False Positives
There are many legitimate applications that leverage shim databases for compatibility purposes for legacy applications

#### Associated Analytic story
* [Suspicious Windows Registry Activities](/stories/suspicious_windows_registry_activities)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A registry activity in $registry_path$ related to shim modication in host $dest$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/registry_keys_for_creating_shim_databases.yml) \| *version*: **4**