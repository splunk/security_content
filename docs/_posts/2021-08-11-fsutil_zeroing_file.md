---
title: "Fsutil Zeroing File"
excerpt: "Indicator Removal on Host"
categories:
  - Endpoint
last_modified_at: 2021-08-11
toc: true
toc_label: ""
tags:
  - Indicator Removal on Host
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious fsutil process to zeroing a target file. This technique was seen in lockbit ransomware where it tries to zero out its malware path as part of its defense evasion after encrypting the compromised host.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-11
- **Author**: Teoderick Contreras, Splunk
- **ID**: 4e5e024e-fabb-11eb-8b8f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=fsutil.exe Processes.process="*setzerodata*" by Processes.user Processes.process_name Processes.parent_process_name Processes.dest  Processes.process Processes.parent_process 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `fsutil_zeroing_file_filter`
```

#### Associated Analytic Story
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Processes.user
* Processes.process_name
* Processes.parent_process_name
* Processes.dest
* Processes.process
* Processes.parent_process


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 60 | 90 | Possible file data deletion on $dest$ using $process$ |




#### Reference

* [https://app.any.run/tasks/e0ac072d-58c9-4f53-8a3b-3e491c7ac5db/](https://app.any.run/tasks/e0ac072d-58c9-4f53-8a3b-3e491c7ac5db/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070/fsutil_file_zero/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070/fsutil_file_zero/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/fsutil_zeroing_file.yml) \| *version*: **1**