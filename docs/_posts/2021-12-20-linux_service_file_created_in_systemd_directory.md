---
title: "Linux Service File Created In Systemd Directory"
excerpt: "Systemd Timers
, Scheduled Task/Job
"
categories:
  - Endpoint
last_modified_at: 2021-12-20
toc: true
toc_label: ""
tags:
  - Systemd Timers
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for suspicious file creation in systemd timer directory in linux platform. systemd is a system and service manager for Linux distributions. From the Windows perspective, this process fulfills the duties of wininit.exe and services.exe combined. At the risk of simplifying the functionality of systemd, it initializes a Linux system and starts relevant services that are defined in service unit files. Adversaries, malware and red teamers may abuse this this feature by stashing systemd service file to persist on the targetted or compromised host.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-12-20
- **Author**: Teoderick Contreras, Splunk
- **ID**: c7495048-61b6-11ec-9a37-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1053.006](https://attack.mitre.org/techniques/T1053/006/) | Systemd Timers | Execution, Persistence, Privilege Escalation |

| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name = *.service Filesystem.file_path IN ("*/etc/systemd/system*", "*/lib/systemd/system*", "*/usr/lib/systemd/system*", "*/run/systemd/system*", "*~/.config/systemd/*", "*~/.local/share/systemd/*","*/etc/systemd/user*", "*/lib/systemd/user*", "*/usr/lib/systemd/user*", "*/run/systemd/user*") by Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.process_guid Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `linux_service_file_created_in_systemd_directory_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_service_file_created_in_systemd_directory_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Administrator or network operator can create file in systemd folders for automation purposes. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A service file named as $file_path$ is created in systemd folder on $dest$ |




#### Reference

* [https://attack.mitre.org/techniques/T1053/006/](https://attack.mitre.org/techniques/T1053/006/)
* [https://www.intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/](https://www.intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/)
* [https://redcanary.com/blog/attck-t1501-understanding-systemd-service-persistence/](https://redcanary.com/blog/attck-t1501-understanding-systemd-service-persistence/)
* [https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/attack-based/persistence/T1053.003_Cron_Activity.xml](https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/attack-based/persistence/T1053.003_Cron_Activity.xml)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.006/service_systemd/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.006/service_systemd/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_service_file_created_in_systemd_directory.yml) \| *version*: **1**