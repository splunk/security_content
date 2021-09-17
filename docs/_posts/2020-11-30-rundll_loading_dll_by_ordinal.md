---
title: "RunDLL Loading DLL By Ordinal"
excerpt: "Rundll32"
categories:
  - Endpoint
last_modified_at: 2020-11-30
toc: true
tags:
  - TTP
  - T1218.011
  - Rundll32
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Installation
---

#### Description

This search looks for executing scripts with rundll32. Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly, may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-11-30
- **Author**: David Dorsey, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = rundll32.exe by Processes.process_name Processes.parent_process_name Processes.process Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `rundll_loading_dll_by_ordinal_filter`
```

#### Associated Analytic Story
* [Unusual Processes](_stories/unusual_processes)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process_name
* Processes.parent_process_name
* Processes.process
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Installation


#### Known False Positives
While not common, loading a DLL under %AppData% and calling a function by ordinal is possible by a legitimate process



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 70.0 | 70 | 100 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/windows-sysmon.log)


_version_: 4