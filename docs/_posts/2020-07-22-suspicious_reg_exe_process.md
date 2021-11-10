---
title: "Suspicious Reg exe Process"
excerpt: "Modify Registry"
categories:
  - Endpoint
last_modified_at: 2020-07-22
toc: true
toc_label: ""
tags:
  - Modify Registry
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for reg.exe being launched from a command prompt not started by the user. When a user launches cmd.exe, the parent process is usually explorer.exe. This search filters out those instances.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-22
- **Author**: David Dorsey, Splunk
- **ID**: a6b3ab4e-dd77-4213-95fa-fc94701995e0


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes where Processes.parent_process_name != explorer.exe Processes.process_name =cmd.exe by Processes.user Processes.process_name Processes.parent_process_name Processes.dest Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| search [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.parent_process_name=cmd.exe Processes.process_name= reg.exe by Processes.parent_process_id Processes.dest Processes.process_name 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| rename parent_process_id as process_id 
|dedup process_id
| table process_id dest] 
| `suspicious_reg_exe_process_filter` 
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Disabling Security Tools](/stories/disabling_security_tools)
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.parent_process_name
* Processes.process_name
* Processes.user
* Processes.parent_process_name
* Processes.dest
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
It&#39;s possible for system administrators to write scripts that exhibit this behavior. If this is the case, the search will need to be modified to filter them out.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Suspicious $Processes.process_path.file_path$ process running with an uncommon parent process $Processes.parent_process_name$ |




#### Reference

* [https://car.mitre.org/wiki/CAR-2013-03-001](https://car.mitre.org/wiki/CAR-2013-03-001)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_reg_exe_process.yml) \| *version*: **4**