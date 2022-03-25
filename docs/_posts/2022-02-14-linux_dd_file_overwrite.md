---
title: "Linux DD File Overwrite"
excerpt: "Data Destruction
"
categories:
  - Endpoint
last_modified_at: 2022-02-14
toc: true
toc_label: ""
tags:
  - Data Destruction
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to look for dd command to overwrite file. This technique was abused by adversaries or threat actor to destroy files or data on specific system or in a large number of host within network to interrupt host avilability, services and many more. This is also used to destroy data where it make the file irrecoverable by forensic techniques through overwriting files, data or local and remote drives.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-02-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9b6aae5e-8d85-11ec-b2ae-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "dd" AND Processes.process = "*of=*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_dd_file_overwrite_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_dd_file_overwrite_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase.

#### Known False Positives
Administrator or network operator can execute this command. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Data Destruction](/stories/data_destruction)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A commandline $process$ executed on $dest$ |




#### Reference

* [https://gtfobins.github.io/gtfobins/dd/](https://gtfobins.github.io/gtfobins/dd/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/linux_dd_file_overwrite/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/linux_dd_file_overwrite/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_dd_file_overwrite.yml) \| *version*: **1**