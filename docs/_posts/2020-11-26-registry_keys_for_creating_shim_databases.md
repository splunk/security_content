---
title: "Registry Keys for Creating SHIM Databases"
excerpt: "Application Shimming"
categories:
  - Endpoint
last_modified_at: 2020-11-26
toc: true
tags:
  - TTP
  - T1546.011
  - Application Shimming
  - Privilege Escalation
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



#### Description

This search looks for registry activity associated with application compatibility shims, which can be leveraged by attackers for various nefarious purposes.

- **ID**: f5f6af30-7aa7-4295-bfe9-07fe87c01bbb
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-11-26
- **Author**: Bhavin Patel, Patrick Bareiss, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1546.011](https://attack.mitre.org/techniques/T1546/011/) | Application Shimming | Privilege Escalation, Persistence |


#### Search

```

| tstats `security_content_summariesonly` count values(Registry.registry_key_name) as registry_key_name min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path=*CurrentVersion\\AppCompatFlags\\Custom* OR Registry.registry_path=*CurrentVersion\\AppCompatFlags\\InstalledSDB* by Registry.dest Registry.user 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `registry_keys_for_creating_shim_databases_filter`
```

#### Associated Analytic Story
* [Suspicious Windows Registry Activities](/stories/suspicious_windows_registry_activities)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### How To Implement
To successfully implement this search, you must populate the Change_Analysis data model. This is typically populated via endpoint detection and response product, such as Carbon Black or other endpoint data sources such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.dest
* Registry.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
There are many legitimate applications that leverage shim databases for compatibility purposes for legacy applications



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 56.0 | 70 | 80 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log)


_version_: 3