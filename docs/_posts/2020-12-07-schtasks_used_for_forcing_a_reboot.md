---
title: "Schtasks used for forcing a reboot"
excerpt: "Scheduled Task, Scheduled Task/Job"
categories:
  - Endpoint
last_modified_at: 2020-12-07
toc: true
toc_label: ""
tags:
  - Scheduled Task
  - Execution
  - Persistence
  - Privilege Escalation
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for flags passed to schtasks.exe on the command-line that indicate that a forced reboot of system is scheduled.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-12-07
- **Author**: Bhavin Patel, Splunk
- **ID**: 1297fb80-f42a-4b4a-9c8a-88c066437cf6


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe Processes.process="*shutdown*" Processes.process="*/create *" by Processes.process_name Processes.parent_process_name Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `schtasks_used_for_forcing_a_reboot_filter`
```

#### Associated Analytic Story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Required field
* _time
* Processes.process
* Processes.process_name
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Administrators may create jobs on systems forcing reboots to perform updates, maintenance, etc.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A schedule task process $process_name$ with force reboot commandline $process$ in host $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/schtask_shutdown/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/schtask_shutdown/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/schtasks_used_for_forcing_a_reboot.yml) \| *version*: **4**