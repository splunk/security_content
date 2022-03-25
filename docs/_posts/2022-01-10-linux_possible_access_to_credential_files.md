---
title: "Linux Possible Access To Credential Files"
excerpt: "/etc/passwd and /etc/shadow
, OS Credential Dumping
"
categories:
  - Endpoint
last_modified_at: 2022-01-10
toc: true
toc_label: ""
tags:
  - /etc/passwd and /etc/shadow
  - OS Credential Dumping
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a possible attempt to dump or access the content of /etc/passwd and /etc/shadow to enable offline credential cracking. "etc/passwd" store user information within linux OS while "etc/shadow" contain the user passwords hash. Adversaries and threat actors may attempt to access this to gain persistence and/or privilege escalation. This anomaly detection can be a good indicator of possible credential dumping technique but it might catch some normal administrator automation scripts or during credential auditing. In this scenario filter is needed.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-01-10
- **Author**: Teoderick Contreras, Splunk
- **ID**: 16107e0e-71fc-11ec-b862-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.008](https://attack.mitre.org/techniques/T1003/008/) | /etc/passwd and /etc/shadow | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN("cat", "nano*","vim*", "vi*")  AND Processes.process IN("*/etc/shadow*", "*/etc/passwd*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_possible_access_to_credential_files_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_possible_access_to_credential_files_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | A commandline $process$ executed on $dest$ |




#### Reference

* [https://askubuntu.com/questions/445361/what-is-difference-between-etc-shadow-and-etc-passwd](https://askubuntu.com/questions/445361/what-is-difference-between-etc-shadow-and-etc-passwd)
* [https://attack.mitre.org/techniques/T1003/008/](https://attack.mitre.org/techniques/T1003/008/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.008/copy_file_stdoutpipe/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.008/copy_file_stdoutpipe/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_possible_access_to_credential_files.yml) \| *version*: **1**