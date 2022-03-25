---
title: "System Processes Run From Unexpected Locations"
excerpt: "Masquerading
, Rename System Utilities
"
categories:
  - Endpoint
last_modified_at: 2020-12-08
toc: true
toc_label: ""
tags:
  - Masquerading
  - Rename System Utilities
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for system processes that typically execute from `C:\Windows\System32\` or `C:\Windows\SysWOW64`.  This may indicate a malicious process that is trying to hide as a legitimate process.\
This detection utilizes a lookup that is deduped `system32` and `syswow64` directories from Server 2016 and Windows 10.\
During triage, review the parallel processes - what process moved the native Windows binary? identify any artifacts on disk and review. If a remote destination is contacted, what is the reputation?

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2020-12-08
- **Author**: David Dorsey, Michael Haag, Splunk
- **ID**: a34aae96-ccf8-4aef-952c-3ea21444444d


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename System Utilities | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes where Processes.process_path !="C:\\Windows\\System32*" Processes.process_path !="C:\\Windows\\SysWOW64*" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_hash 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `is_windows_system_file` 
| `system_processes_run_from_unexpected_locations_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [is_windows_system_file](https://github.com/splunk/security_content/blob/develop/macros/is_windows_system_file.yml)

Note that `system_processes_run_from_unexpected_locations_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_path
* Processes.user
* Processes.dest
* Processes.process_name
* Processes.process_id
* Processes.parent_process_name
* Processes.process_hash


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
This detection may require tuning based on third party applications utilizing native Windows binaries in non-standard paths.

#### Associated Analytic story
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)
* [Unusual Processes](/stories/unusual_processes)
* [Ransomware](/stories/ransomware)
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | System process running from unexpected location on $dest$ |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.yaml)
* [https://attack.mitre.org/techniques/T1036/003/](https://attack.mitre.org/techniques/T1036/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/system_processes_run_from_unexpected_locations.yml) \| *version*: **6**