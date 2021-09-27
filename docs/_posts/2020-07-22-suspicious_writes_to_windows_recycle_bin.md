---
title: "Suspicious writes to windows Recycle Bin"
excerpt: "Masquerading"
categories:
  - Endpoint
last_modified_at: 2020-07-22
toc: true
tags:
  - TTP
  - T1036
  - Masquerading
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects writes to the recycle bin by a process other than explorer.exe.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-22
- **Author**: Rico Valdez, Splunk
- **ID**: b5541828-8ffd-4070-9d95-b3da4de924cb


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |



#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name FROM datamodel=Endpoint.Filesystem where Filesystem.file_path = "*$Recycle.Bin*" by Filesystem.process_id Filesystem.dest 
| `drop_dm_object_name("Filesystem")`
| search [
| tstats `security_content_summariesonly` values(Processes.user) as user values(Processes.process_name) as process_name values(Processes.parent_process_name) as parent_process_name FROM datamodel=Endpoint.Processes where Processes.process_name != "explorer.exe" by Processes.process_id Processes.dest
| `drop_dm_object_name("Processes")` 
| table process_id dest] 
| `suspicious_writes_to_windows_recycle_bin_filter`
```

#### Associated Analytic Story
* [Collection and Staging](/stories/collection_and_staging)


#### How To Implement
To successfully implement this search you need to be ingesting information on filesystem and process logs responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Filesystem` nodes.

#### Required field
* _time
* Filesystem.file_path
* Filesystem.file_name
* Filesystem.process_id
* Filesystem.dest
* Processes.user
* Processes.process_name
* Processes.parent_process_name
* Processes.process_id
* Processes.dest


#### Kill Chain Phase


#### Known False Positives
Because the Recycle Bin is a hidden folder in modern versions of Windows, it would be unusual for a process other than explorer.exe to write to it. Incidents should be investigated as appropriate.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 28.0 | 40 | 70 | Suspicious writes to windows Recycle Bin process $Processes.process_name$ |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/write_to_recycle_bin/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/write_to_recycle_bin/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_writes_to_windows_recycle_bin.yml) \| *version*: **4**