---
title: "Detect Path Interception By Creation Of program exe"
excerpt: "Path Interception by Unquoted Path
, Hijack Execution Flow
"
categories:
  - Endpoint
last_modified_at: 2020-07-03
toc: true
toc_label: ""
tags:
  - Path Interception by Unquoted Path
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

The detection Detect Path Interception By Creation Of program exe is detecting the abuse of unquoted service paths, which is a popular technique for privilege escalation. 

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2020-07-03
- **Author**: Patrick Bareiss, Splunk
- **ID**: cbef820c-e1ff-407f-887f-0a9240a2d477


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1574.009](https://attack.mitre.org/techniques/T1574/009/) | Path Interception by Unquoted Path | Defense Evasion, Persistence, Privilege Escalation |

| [T1574](https://attack.mitre.org/techniques/T1574/) | Hijack Execution Flow | Defense Evasion, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=services.exe by Processes.user Processes.process_name Processes.process Processes.dest 
| `drop_dm_object_name(Processes)` 
| rex field=process "^.*?\\\\(?<service_process>[^\\\\]*\.(?:exe
|bat
|com
|ps1))" 
| eval process_name = lower(process_name) 
| eval service_process = lower(service_process) 
| where process_name != service_process 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_path_interception_by_creation_of_program_exe_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_path_interception_by_creation_of_program_exe_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model.

#### Known False Positives
unknown

#### Associated Analytic story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to perform privilege escalation by using unquoted service paths. |




#### Reference

* [https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae](https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.009/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.009/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_path_interception_by_creation_of_program_exe.yml) \| *version*: **3**