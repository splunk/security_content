---
title: "Linux File Creation In Profile Directory"
excerpt: "Unix Shell Configuration Modification
, Event Triggered Execution
"
categories:
  - Endpoint
last_modified_at: 2021-12-20
toc: true
toc_label: ""
tags:
  - Unix Shell Configuration Modification
  - Event Triggered Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for suspicious file creation in /etc/profile.d directory to automatically execute scripts by shell upon boot up of a linux machine. This technique is commonly abused by adversaries, malware and red teamers as a persistence mechanism to the targeted or compromised host. This Anomaly detection is a good indicator that someone wants to run a code after boot up which can be done also by the administrator or network operator for automation purposes.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-20
- **Author**: Teoderick Contreras, Splunk
- **ID**: 46ba0082-61af-11ec-9826-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1546.004](https://attack.mitre.org/techniques/T1546/004/) | Unix Shell Configuration Modification | Persistence, Privilege Escalation |

| [T1546](https://attack.mitre.org/techniques/T1546/) | Event Triggered Execution | Persistence, Privilege Escalation |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*/etc/profile.d/*") by Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.process_guid Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `linux_file_creation_in_profile_directory_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **linux_file_creation_in_profile_directory_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.dest
* Filesystem.file_create_time
* Filesystem.file_name
* Filesystem.process_guid
* Filesystem.file_path


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the file name, file path, and process_guid executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase.

#### Known False Positives
Administrator or network operator can create file in profile.d folders for automation purposes. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A file $file_name$ is created in $file_path$ on $dest$ |


#### Reference

* [https://attack.mitre.org/techniques/T1546/004/](https://attack.mitre.org/techniques/T1546/004/)
* [https://www.intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/](https://www.intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.004/linux_init_profile/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.004/linux_init_profile/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_file_creation_in_profile_directory.yml) \| *version*: **1**