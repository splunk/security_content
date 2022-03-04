---
title: "Linux File Creation In Init Boot Directory"
excerpt: "RC Scripts
, Boot or Logon Initialization Scripts
"
categories:
  - Endpoint
last_modified_at: 2021-12-20
toc: true
toc_label: ""
tags:

  - RC Scripts
  - Boot or Logon Initialization Scripts
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for suspicious file creation on init system directories for automatic execution of script or file upon boot up. This technique is commonly abuse by adversaries, malware author and red teamer to persist on the targeted or compromised host. This behavior can be executed or use by an administrator or network operator to add script files or binary files as part of a task or automation. filter is needed.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-20
- **Author**: Teoderick Contreras, Splunk
- **ID**: 97d9cfb2-61ad-11ec-bb2d-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1037.004](https://attack.mitre.org/techniques/T1037/004/) | RC Scripts | Persistence, Privilege Escalation |

| [T1037](https://attack.mitre.org/techniques/T1037/) | Boot or Logon Initialization Scripts | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*/etc/init.d/*", "*/etc/rc.d/*", "*/sbin/init.d/*", "*/etc/rc.local*") by Filesystem.dest Filesystem.file_name Filesystem.process_guid Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `linux_file_creation_in_init_boot_directory_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_file_creation_in_init_boot_directory_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.dest
* Filesystem.file_create_time
* Filesystem.file_name
* Filesystem.process_guid
* Filesystem.file_path


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the file name, file path, and process_guid executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase

#### Known False Positives
Administrator or network operator can create file in this folders for automation purposes. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | A file $file_name$ is created in $file_path$ on $dest$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/](https://www.intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.004/linux_init_profile/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.004/linux_init_profile/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_file_creation_in_init_boot_directory.yml) \| *version*: **1**