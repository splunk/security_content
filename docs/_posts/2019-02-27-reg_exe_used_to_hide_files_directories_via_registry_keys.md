---
title: "Reg exe used to hide files directories via registry keys"
excerpt: "Hidden Files and Directories
"
categories:
  - Deprecated
last_modified_at: 2019-02-27
toc: true
toc_label: ""
tags:
  - Hidden Files and Directories
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for command-line arguments used to hide a file or directory using the reg add command.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2019-02-27
- **Author**: Bhavin Patel, Splunk
- **ID**: 61a7d1e6-f5d4-41d9-a9be-39a1ffe69459


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1564.001](https://attack.mitre.org/techniques/T1564/001/) | Hidden Files and Directories | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = reg.exe Processes.process="*add*" Processes.process="*Hidden*" Processes.process="*REG_DWORD*" by Processes.process_name Processes.parent_process_name Processes.dest Processes.user
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)`
| regex process = "(/d\s+2)" 
| `reg_exe_used_to_hide_files_directories_via_registry_keys_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `reg_exe_used_to_hide_files_directories_via_registry_keys_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model.

#### Known False Positives
None at the moment

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Suspicious Windows Registry Activities](/stories/suspicious_windows_registry_activities)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/reg_exe_used_to_hide_files_directories_via_registry_keys.yml) \| *version*: **2**