---
title: "Linux deletion Of SSH Hash Conf"
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

This analytic is to detect a deletion of ssh key in a linux machine. attacker may delete or modify ssh key to impair some security features or act as defense evasion in compromised linux machine. This Anomaly can be also a good indicator of a malware trying to wipe or delete several files in a compromised host as part of its destructive payload like what acidrain malware does in linux or router machines. This detection can be a good pivot to check what process and user tries to delete this type of files which is not so common and need further investigation.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: 73a56508-1cf5-4df7-b8d9-5737fbdc27d2


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.action=deleted AND Filesystem.file_path IN ("/etc/ssh/*", "~/.ssh/*") by _time span=1h Filesystem.file_name Filesystem.file_path Filesystem.dest Filesystem.process_guid Filesystem.action 
| `drop_dm_object_name(Filesystem)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [ 
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.parent_process_name != unknown by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_path Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name action] 
| table  process_name process proc_guid file_name file_path action _time parent_process_name parent_process  process_path dest user 
| `linux_deletion_of_ssh_hash_conf_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **linux_deletion_of_ssh_hash_conf_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Administrator or network operator can execute this command. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Acidrain](/stories/acidrain)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | a $process_name$ deleting a SSH key in $dest$ |


#### Reference

* [https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/](https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/acidrain/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/acidrain/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_deletion_of_ssh_hash_conf.yml) \| *version*: **1**