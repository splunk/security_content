---
title: "Detect Renamed 7-Zip"
excerpt: "Archive via Utility"
categories:
  - Endpoint
last_modified_at: 2021-05-19
toc: true
tags:
  - TTP
  - T1560.001
  - Archive via Utility
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exfiltration
---



#### Description

The following analytic identifies renamed 7-Zip usage using Sysmon. At this stage of an attack, review parallel processes and file modifications for data that is staged or potentially have been exfiltrated. This analytic utilizes the OriginalFileName to capture the renamed process.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-19
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Collection |


#### Search

```
`sysmon` EventID=1 (OriginalFileName=7z*.exe AND process_name!=7z*.exe) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, parent_process_name, process_name, OriginalFileName, process_path, CommandLine 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_renamed_7_zip_filter`
```

#### Associated Analytic Story
* [Collection and Staging](_stories/collection_and_staging)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* dest
* User
* parent_process_name
* process_name
* OriginalFileName
* process_path
* CommandLine
* Product


#### Kill Chain Phase
* Exfiltration


#### Known False Positives
Limited false positives, however this analytic will need to be modified for each environment if Sysmon is not used.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 27.0 | 30 | 90 |



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility/windows-sysmon.log)


_version_: 1