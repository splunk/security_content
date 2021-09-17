---
title: "Schtasks Run Task On Demand"
excerpt: "Scheduled Task/Job"
categories:
  - Endpoint
last_modified_at: 2021-05-07
toc: true
tags:
  - TTP
  - T1053
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

#### Description

This analytic identifies an on demand run of a Windows Schedule Task through shell or command-line. This technique has been used by adversaries that force to run their created Schedule Task as their persistence mechanism or for lateral movement as part of their malicious attack to the compromised machine.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-07
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime  from datamodel=Endpoint.Processes where Processes.process_name = "schtasks.exe" Processes.process = "*/run*" by Processes.process_name Processes.parent_process_name Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `schtasks_run_task_on_demand_filter`
```

#### Associated Analytic Story
* [XMRig](_stories/xmrig)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed schtasks.exe may be used.

#### Required field
* _time
* Processes.process
* Processes.process_id
* Processes.process_name
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Administrators may use to debug Schedule Task entries. Filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 48.0 | 60 | 80 |



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)


_version_: 1