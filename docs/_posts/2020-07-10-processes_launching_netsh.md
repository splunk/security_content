---
title: "Processes launching netsh"
excerpt: "Disable or Modify System Firewall"
categories:
  - Endpoint
last_modified_at: 2020-07-10
toc: true
tags:
  - TTP
  - T1562.004
  - Disable or Modify System Firewall
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



#### Description

This search looks for processes launching netsh.exe. Netsh is a command-line scripting utility that allows you to, either locally or remotely, display or modify the network configuration of a computer that is currently running. Netsh can be used as a persistence proxy technique to execute a helper DLL when netsh.exe is executed. In this search, we are looking for processes spawned by netsh.exe and executing commands via the command line.

- **ID**: b89919ed-fe5f-492c-b139-95dbb162040e
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-10
- **Author**: Josef Kuepker, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1562.004](https://attack.mitre.org/techniques/T1562/004/) | Disable or Modify System Firewall | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) AS Processes.process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process=*netsh* by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.user Processes.dest 
|`drop_dm_object_name("Processes")` 
|`security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
|`processes_launching_netsh_filter`
```

#### Associated Analytic Story
* [Netsh Abuse](/stories/netsh_abuse)
* [Disabling Security Tools](/stories/disabling_security_tools)
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)


#### How To Implement
To successfully implement this search, you must be ingesting data that records process activity from your hosts to populate the endpoint data model

#### Required field
* _time
* Processes.process
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.user
* Processes.dest


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Some VPN applications are known to launch netsh.exe. Outside of these instances, it is unusual for an executable to launch netsh.exe and run commands.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 42.0 | 60 | 70 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/processes_launching_netsh.yml) \| *version*: **3**