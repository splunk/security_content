---
title: "Detect Prohibited Applications Spawning cmd exe"
excerpt: "Windows Command Shell"
categories:
  - Endpoint
last_modified_at: 2020-11-10
toc: true
tags:
  - Hunting
  - T1059.003
  - Windows Command Shell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

This search looks for executions of cmd.exe spawned by a process that is often abused by attackers and that does not typically launch cmd.exe.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-11-10
- **Author**: Bhavin Patel, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |


#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.parent_process_name Processes.process_name Processes.dest Processes.user
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
|search [`prohibited_apps_launching_cmd`] 
| `detect_prohibited_applications_spawning_cmd_exe_filter`
```

#### Associated Analytic Story
* [Suspicious Command-Line Executions](_stories/suspicious_command-line_executions)
* [Suspicious MSHTA Activity](_stories/suspicious_mshta_activity)
* [Suspicious Zoom Child Processes](_stories/suspicious_zoom_child_processes)
* [NOBELIUM Group](_stories/nobelium_group)


#### How To Implement
You must be ingesting data that records process activity from your hosts and populates the Endpoint data model with the resultant dataset. This search includes a lookup file, `prohibited_apps_launching_cmd.csv`, that contains a list of processes that should not be spawning cmd.exe. You can modify this lookup to better suit your environment.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
There are circumstances where an application may legitimately execute and interact with the Windows command-line interface. Investigate and modify the lookup file, as appropriate.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 80.0 | 80 | 100 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/powershell_spawn_cmd/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/powershell_spawn_cmd/windows-sysmon.log)


_version_: 5