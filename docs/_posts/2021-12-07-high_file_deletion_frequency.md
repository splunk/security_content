---
title: "High File Deletion Frequency"
excerpt: "Data Destruction"
categories:
  - Endpoint
last_modified_at: 2021-12-07
toc: true
toc_label: ""
tags:
  - Data Destruction
  - Impact
  - Splunk Behavioral Analytics
  - Endpoint_Filesystem
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection detects a high amount of file deletions in a short time for specific file types. This can be an indicator for a malicious insider.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Filesystem](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointFilesystem)
- **Last Updated**: 2021-12-07
- **Author**: Patrick Bareiss, Splunk
- **ID**: b6200efd-13bd-4336-920a-057b25bbcfaf


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| eval action=ucast(map_get(input_event, "action"), "string", null), process=ucast(map_get(input_event, "process"), "string", null), file_name=ucast(map_get(input_event, "file_name"), "string", null), file_path=ucast(map_get(input_event, "file_path"), "string", null), dest_user_id=ucast(map_get(input_event, "dest_user_id"), "string", null), dest_device_id=ucast(map_get(input_event, "dest_device_id"), "string", null) 
| where "Endpoint_Filesystem" IN(_datamodels) 
| where action="deleted" 
| where like(file_name, "%.cmd") OR like(file_name, "%.ini") OR like(file_name, "%.gif") OR like(file_name, "%.jpg") OR like(file_name, "%.jpeg") OR like(file_name, "%.db") OR like(file_name, "%.doc%") OR like(file_name, "%.ps1") OR like(file_name, "%.xls%") OR like(file_name, "%.ppt%") OR like(file_name, "%.bmp") OR like(file_name, "%.zip") OR like(file_name, "%.rar") OR like(file_name, "%.7z") OR like(file_name, "%.chm") OR like(file_name, "%.png") OR like(file_name, "%.log") OR like(file_name, "%.vbs") OR like(file_name, "%.js") 
| stats count(file_name) AS count BY dest_user_id, dest_device_id, span(timestamp, 10m) 
| where count > 20 
| eval start_time=window_start, end_time=window_end, entities=mvappend(dest_user_id, dest_device_id), body=create_map(["count", count]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `high_file_deletion_frequency_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* action
* process
* file_name
* file_path


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesytem` node.

#### Known False Positives
user may delete bunch of pictures or files in a folder.

#### Associated Analytic story
* [Clop Ransomware](/stories/clop_ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | High frequency file deletion activity detected on host $Computer$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/excessive_file_deletions/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/excessive_file_deletions/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/high_file_deletion_frequency.yml) \| *version*: **1**