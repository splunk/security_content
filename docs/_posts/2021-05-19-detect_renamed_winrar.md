---
title: "Detect Renamed WinRAR"
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
  - Exploitation
  - Exfiltration
---



[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

The following analtyic identifies renamed instances of `WinRAR.exe`. In most cases, it is not common for WinRAR to be used renamed, however it is common to be installed by a third party application and executed from a non-standard path. In this instance, we are using `OriginalFileName` from Sysmon to determine if the process is WinRAR. During triage, validate additional metadata from the binary that this is `WinRAR`. Review parallel processes and file modifications.

- **ID**: 1b7bfb2c-b8e6-11eb-99ac-acde48001122
- **Type**: TTP
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
`sysmon` EventID=1 (Product=WinRAR OR OriginalFileName=WinRAR.exe) process_name!=rar.exe process_name!=winrar.exe 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, parent_process_name, process_name, OriginalFileName, process_path, CommandLine Product 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_renamed_winrar_filter`
```

#### Associated Analytic Story
* [Collection and Staging](/stories/collection_and_staging)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Modify query for specific EDR products as needed.

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
* Exploitation
* Exfiltration


#### Known False Positives
Unknown. It is possible third party applications use renamed instances of WinRAR.



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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_renamed_winrar.yml) \| *version*: **1**