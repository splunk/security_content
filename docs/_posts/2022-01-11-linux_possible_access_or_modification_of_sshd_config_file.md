---
title: "Linux Possible Access Or Modification Of sshd Config File"
excerpt: "SSH Authorized Keys
, Account Manipulation
"
categories:
  - Endpoint
last_modified_at: 2022-01-11
toc: true
toc_label: ""
tags:
  - SSH Authorized Keys
  - Account Manipulation
  - Persistence
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to look for suspicious process command-line that might be accessing or modifying sshd_config. This file is the ssh configuration file that might be modify by threat actors or adversaries to redirect port connection, allow user using authorized key generated during attack. This anomaly detection might catch noise from administrator auditing or modifying ssh configuration file. In this scenario filter is needed

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-01-11
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7a85eb24-72da-11ec-ac76-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | SSH Authorized Keys | Persistence |

| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN("cat", "nano*","vim*", "vi*")  AND Processes.process IN("*/etc/ssh/sshd_config") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_possible_access_or_modification_of_sshd_config_file_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_possible_access_or_modification_of_sshd_config_file_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Administrator or network operator can use this commandline for automation purposes. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | a commandline $process$ executed on $dest$ |




#### Reference

* [https://www.hackingarticles.in/ssh-penetration-testing-port-22/](https://www.hackingarticles.in/ssh-penetration-testing-port-22/)
* [https://attack.mitre.org/techniques/T1098/004/](https://attack.mitre.org/techniques/T1098/004/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/ssh_authorized_keys/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/ssh_authorized_keys/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_possible_access_or_modification_of_sshd_config_file.yml) \| *version*: **1**