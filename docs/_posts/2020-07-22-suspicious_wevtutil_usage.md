---
title: "Suspicious wevtutil Usage"
excerpt: "Clear Windows Event Logs"
categories:
  - Endpoint
last_modified_at: 2020-07-22
toc: true
tags:
  - TTP
  - T1070.001
  - Clear Windows Event Logs
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



#### Description

The wevtutil.exe application is the windows event log utility. This searches for wevtutil.exe with parameters for clearing the application, security, setup, or system event logs.

- **ID**: 2827c0fd-e1be-4868-ae25-59d28e0f9d4f
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-22
- **Author**: David Dorsey, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = wevtutil.exe Processes.process="*cl*" (Processes.process="*System*" OR Processes.process="*Security*" OR Processes.process="*Setup*" OR Processes.process="*Application*") by Processes.process_name Processes.parent_process_name Processes.dest Processes.user
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `suspicious_wevtutil_usage_filter`
```

#### Associated Analytic Story
* [Windows Log Manipulation](/stories/windows_log_manipulation)
* [Ransomware](/stories/ransomware)
* [Clop Ransomware](/stories/clop_ransomware)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

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
The wevtutil.exe application is a legitimate Windows event log utility. Administrators may use it to manage Windows event logs.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 28.0 | 40 | 70 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-sysmon.log)


_version_: 3