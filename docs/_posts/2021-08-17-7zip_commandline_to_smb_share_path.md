---
title: "7zip CommandLine To SMB Share Path"
excerpt: "Archive via Utility"
categories:
  - Endpoint
last_modified_at: 2021-08-17
toc: true
tags:
  - Hunting
  - T1560.001
  - Archive via Utility
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious 7z process with commandline pointing to SMB network share. This technique was seen in CONTI LEAK tools where it use 7z to archive a sensitive files and place it in network share tmp folder. This search is a good hunting query that may give analyst a hint why specific user try to archive a file pointing to SMB user which is un usual.

- **ID**: 01d29b48-ff6f-11eb-b81e-acde48001122
- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-17
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Collection |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name ="7z.exe" OR Processes.process_name = "7za.exe" OR Processes.original_file_name = "7z.exe" OR Processes.original_file_name =  "7za.exe") AND (Processes.process="*\\C$\\*" OR Processes.process="*\\Admin$\\*" OR Processes.process="*\\IPC$\\*") by Processes.original_file_name Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.parent_process_id Processes.process_id  Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `7zip_commandline_to_smb_share_path_filter`
```

#### Associated Analytic Story
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed 7z.exe may be used.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 25.0 | 50 | 50 |



#### Reference

* [https://threadreaderapp.com/thread/1423361119926816776.html](https://threadreaderapp.com/thread/1423361119926816776.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/conti_leak/windows-sysmon_7z.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/conti_leak/windows-sysmon_7z.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/7zip_commandline_to_smb_share_path.yml) \| *version*: **1**