---
title: "Recursive Delete of Directory In Batch CMD"
excerpt: "File Deletion"
categories:
  - Endpoint
last_modified_at: 2021-06-22
toc: true
tags:
  - TTP
  - T1070.004
  - File Deletion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

This search is to detect a suspicious commandline designed to delete files or directory recursive using batch command. This technique was seen in ransomware (reddot) where it it tries to delete the files in recycle bin to impaire user from recovering deleted files.

- **ID**: ba570b3a-d356-11eb-8358-acde48001122
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-22
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe Processes.process=*/c*  Processes.process=* rd * Processes.process="*/s*" Processes.process="*/q*" by Processes.user Processes.process_name Processes.parent_process_name Processes.parent_process Processes.process Processes.process_id Processes.dest 
|`drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `recursive_delete_of_directory_in_batch_cmd_filter`
```

#### Associated Analytic Story
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.parent_process
* Processes.process_id
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
network operator may use this batch command to delete recursively a directory or files within directory




#### Reference

* [https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/](https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/recursive_delete_of_directory_in_batch_cmd.yml) \| *version*: **1**