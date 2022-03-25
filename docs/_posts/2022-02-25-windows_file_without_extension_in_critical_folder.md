---
title: "Windows File Without Extension In Critical Folder"
excerpt: "Data Destruction
"
categories:
  - Endpoint
last_modified_at: 2022-02-25
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

This analytic is to look for suspicious file creation in the critical folder like "System32\Drivers" folder without file extension. This artifacts was seen in latest hermeticwiper where it drops its driver component in Driver Directory both the compressed(without file extension) and the actual driver component (with .sys file extension). This TTP is really a good indication that a host might be compromised by this destructive malware that wipes the boot sector of the system.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-02-25
- **Author**: Teoderick Contreras, Bhavin Patel, Splunk
- **ID**: 0dbcac64-963c-11ec-bf04-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*\\System32\\drivers\\*", "*\\syswow64\\drivers\\*") by _time span=5m Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_guid Filesystem.file_create_time 
| `drop_dm_object_name(Filesystem)` 
| rex field="file_name" "\.(?<extension>[^\.]*$)" 
| where isnull(extension) 
| join process_guid [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=5m Processes.process_name Processes.dest Processes.process_guid Processes.user 
| `drop_dm_object_name(Processes)`] 
| stats count min(_time) as firstTime max(_time) as lastTime by dest process_name process_guid file_name file_path file_create_time user 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_file_without_extension_in_critical_folder_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `windows_file_without_extension_in_critical_folder_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.file_create_time
* Filesystem.process_id
* Filesystem.file_name
* Filesystem.user
* Filesystem.file_path
* Filesystem.dest
* Processes.process_name
* Processes.dest
* Processes.process_guid
* Processes.user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the Filesystem responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesystem` node.

#### Known False Positives
Unknown at this point

#### Associated Analytic story
* [Data Destruction](/stories/data_destruction)
* [Hermetic Wiper](/stories/hermetic_wiper)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | Driver file with out file extension drop in $file_path$ in $dest$ |




#### Reference

* [https://blog.talosintelligence.com/2022/02/threat-advisory-hermeticwiper.html](https://blog.talosintelligence.com/2022/02/threat-advisory-hermeticwiper.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_file_without_extension_in_critical_folder.yml) \| *version*: **1**