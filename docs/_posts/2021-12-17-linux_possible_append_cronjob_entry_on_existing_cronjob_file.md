---
title: "Linux Possible Append Cronjob Entry on Existing Cronjob File"
excerpt: "Cron
, Scheduled Task/Job
"
categories:
  - Endpoint
last_modified_at: 2021-12-17
toc: true
toc_label: ""
tags:
  - Cron
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

This analytic looks for possible suspicious commandline that may use to append a code to any existing cronjob files for persistence or privilege escalation. This technique is commonly abused by malware, adversaries and red teamers to automatically execute their code within a existing or sometimes in normal cronjob script file.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-12-17
- **Author**: Teoderick Contreras, Splunk
- **ID**: b5b91200-5f27-11ec-bb4e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron | Execution, Persistence, Privilege Escalation |

| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where Processes.process = "*echo*" AND Processes.process IN("*/etc/cron*", "*/var/spool/cron/*", "*/etc/anacrontab*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_possible_append_cronjob_entry_on_existing_cronjob_file_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_possible_append_cronjob_entry_on_existing_cronjob_file_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
| 49.0 | 70 | 70 | A commandline $process$ that may modify cronjob file in $dest$ |




#### Reference

* [https://attack.mitre.org/techniques/T1053/003/](https://attack.mitre.org/techniques/T1053/003/)
* [https://blog.aquasec.com/threat-alert-kinsing-malware-container-vulnerability](https://blog.aquasec.com/threat-alert-kinsing-malware-container-vulnerability)
* [https://www.intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/](https://www.intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.003/cronjobs_entry/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.003/cronjobs_entry/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_possible_append_cronjob_entry_on_existing_cronjob_file.yml) \| *version*: **1**