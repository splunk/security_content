---
title: "Linux Possible Append Command To At Allow Config File"
excerpt: "At (Linux)
, Scheduled Task/Job
"
categories:
  - Endpoint
last_modified_at: 2021-12-17
toc: true
toc_label: ""
tags:
  - At (Linux)
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

This analytic looks for suspicious commandline that may use to append user entry to /etc/at.allow or /etc/at.deny. These 2 files are commonly abused by malware, adversaries or red teamers to persist on the targeted or compromised host. These config file can restrict user that can only execute at application (another schedule task application in linux). attacker can create a user or add the compromised username to that config file to execute at to schedule it malicious code. This anomaly detection can be a good indicator to investigate further the entry in created config file and who created it to verify if it is a false positive.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-12-17
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7bc20606-5f40-11ec-a586-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1053.001](https://attack.mitre.org/techniques/T1053/001/) | At (Linux) | Execution, Persistence, Privilege Escalation |

| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where Processes.process = "*echo*" AND Processes.process IN("*/etc/at.allow", "*/etc/at.deny") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_possible_append_command_to_at_allow_config_file_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_possible_append_command_to_at_allow_config_file_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
| 9.0 | 30 | 30 | A commandline $process$ that may modify at allow config file in $dest$ |




#### Reference

* [https://linuxize.com/post/at-command-in-linux/](https://linuxize.com/post/at-command-in-linux/)
* [https://attack.mitre.org/techniques/T1053/001/](https://attack.mitre.org/techniques/T1053/001/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.001/at_execution/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.001/at_execution/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_possible_append_command_to_at_allow_config_file.yml) \| *version*: **1**