---
title: "Linux High Frequency Of File Deletion In Etc Folder"
excerpt: "Data Destruction
, File Deletion
, Indicator Removal on Host
"
categories:
  - Endpoint
last_modified_at: 2022-04-12
toc: true
toc_label: ""
tags:
  - Data Destruction
  - File Deletion
  - Indicator Removal on Host
  - Impact
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a high frequency of file deletion relative to process name and process id /etc/ folder. These events was seen in acidrain wiper malware where it tries to delete all files in a non-standard directory in linux directory. This detection already contains some filter that might cause false positive during our testing. But we recommend to add more filter if needed.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9d867448-2aff-4d07-876c-89409a752ff8


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |

| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Defense Evasion |

| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` values(Filesystem.file_name) as deletedFileNames values(Filesystem.file_path) as deletedFilePath dc(Filesystem.file_path) as numOfDelFilePath count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.action=deleted Filesystem.file_path = "/etc/*" by _time span=1h  Filesystem.dest Filesystem.process_guid Filesystem.action 
| `drop_dm_object_name(Filesystem)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [ 
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.parent_process_name != unknown NOT (Processes.parent_process_name IN ("/usr/bin/dpkg", "*usr/bin/python*", "*/usr/bin/apt-*", "/bin/rm", "*splunkd", "/usr/bin/mandb")) by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_path Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name action] 
| table  process_name process proc_guid action _time  deletedFileNames deletedFilePath numOfDelFilePath parent_process_name parent_process  process_path dest user 
| where  numOfDelFilePath >= 200 
| `linux_high_frequency_of_file_deletion_in_etc_folder_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **linux_high_frequency_of_file_deletion_in_etc_folder_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.dest
* Filesystem.file_create_time
* Filesystem.file_name
* Filesystem.process_guid
* Filesystem.file_path
* Filesystem.action
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process_path
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase.

#### Known False Positives
linux package installer/uninstaller may cause this event. Please update you filter macro to remove false positives.

#### Associated Analytic story
* [AcidRain](/stories/acidrain)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | a $process_name$ deleting multiple files in /etc/ folder in $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/](https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/acidrain/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/acidrain/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_high_frequency_of_file_deletion_in_etc_folder.yml) \| *version*: **1**