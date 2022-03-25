---
title: "Execution of File With Spaces Before Extension"
excerpt: "Rename System Utilities
"
categories:
  - Deprecated
last_modified_at: 2020-11-19
toc: true
toc_label: ""
tags:
  - Rename System Utilities
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for processes launched from files with at least five spaces in the name before the extension. This is typically done to obfuscate the file extension by pushing it outside of the default view.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2020-11-19
- **Author**: Rico Valdez, Splunk
- **ID**: ab0353e6-a956-420b-b724-a8b4846d5d5a


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename System Utilities | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process_path) as process_path min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process = "*     .*" by Processes.dest Processes.user Processes.process Processes.process_name 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name(Processes)` 
| `execution_of_file_with_spaces_before_extension_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `execution_of_file_with_spaces_before_extension_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_path
* Processes.process
* Processes.dest
* Processes.user
* Processes.process_name


#### How To Implement
To successfully implement this search, you must be ingesting data that records process activity from your hosts to populate the endpoint data model in the processes node. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
None identified.

#### Associated Analytic story
* [Windows File Extension and Association Abuse](/stories/windows_file_extension_and_association_abuse)
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)


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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/execution_of_file_with_spaces_before_extension.yml) \| *version*: **3**