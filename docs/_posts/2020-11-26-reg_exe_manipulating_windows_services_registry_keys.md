---
title: "Reg exe Manipulating Windows Services Registry Keys"
excerpt: "Services Registry Permissions Weakness
, Hijack Execution Flow
"
categories:
  - Endpoint
last_modified_at: 2020-11-26
toc: true
toc_label: ""
tags:
  - Services Registry Permissions Weakness
  - Hijack Execution Flow
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for reg.exe modifying registry keys that define Windows services and their configurations.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2020-11-26
- **Author**: Rico Valdez, Splunk
- **ID**: 8470d755-0c13-45b3-bd63-387a373c10cf


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1574.011](https://attack.mitre.org/techniques/T1574/011/) | Services Registry Permissions Weakness | Defense Evasion, Persistence, Privilege Escalation |

| [T1574](https://attack.mitre.org/techniques/T1574/) | Hijack Execution Flow | Defense Evasion, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as process_name values(Processes.parent_process_name) as parent_process_name values(Processes.user) as user FROM datamodel=Endpoint.Processes where Processes.process_name=reg.exe Processes.process=*reg* Processes.process=*add* Processes.process=*Services* by Processes.process_id Processes.dest Processes.process 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `reg_exe_manipulating_windows_services_registry_keys_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `reg_exe_manipulating_windows_services_registry_keys_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.parent_process_name
* Processes.user
* Processes.process
* Processes.process_id
* Processes.dest


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Known False Positives
It is unusual for a service to be created or modified by directly manipulating the registry. However, there may be legitimate instances of this behavior. It is important to validate and investigate, as appropriate.

#### Associated Analytic story
* [Windows Service Abuse](/stories/windows_service_abuse)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Installation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 75 | 60 | A reg.exe process $process_name$ with commandline $process$ in host $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.011/change_registry_path_service/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.011/change_registry_path_service/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/reg_exe_manipulating_windows_services_registry_keys.yml) \| *version*: **5**