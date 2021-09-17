---
title: "Schtasks scheduling job on remote system"
excerpt: "Scheduled Task"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
tags:
  - TTP
  - T1053.005
  - Scheduled Task
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---

#### Description

This search looks for flags passed to schtasks.exe on the command-line that indicate a job is being scheduled on a remote system.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = schtasks.exe Processes.process="*/create*" (Processes.process="* /s *" OR Processes.process="* /S *") by Processes.process_name Processes.process Processes.parent_process_name Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `schtasks_scheduling_job_on_remote_system_filter`
```

#### Associated Analytic Story
* [Lateral Movement](_stories/lateral_movement)
* [NOBELIUM Group](_stories/nobelium_group)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Administrators may create jobs on remote systems, but this activity is usually limited to a small set of hosts or users. It is important to validate and investigate as appropriate.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 63.0 | 70 | 90 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/atomic_red_team/windows-sysmon.log)


_version_: 4