---
title: "Excessive Usage Of Taskkill"
excerpt: "Disable or Modify Tools"
categories:
  - Endpoint
last_modified_at: 2021-05-04
toc: true
tags:
  - Anomaly
  - T1562.001
  - Disable or Modify Tools
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

#### Description

This analytic identifies excessive usage of `taskkill.exe` application. This application is commonly used by adversaries to evade detections by killing security product processes or even other processes to evade detection.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-04
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "taskkill.exe"  by Processes.parent_process_name Processes.process_name Processes.dest Processes.user _time span=1m 
| where count >=10 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_usage_of_taskkill_filter`
```

#### Associated Analytic Story
* [XMRig](_stories/xmrig)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed taskkill.exe may be used.

#### Required field
* _time
* Processes.parent_process_name
* Processes.process_name
* Processes.dest
* Processes.user
* Processes.process
* Processes.process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Unknown. Filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 28.0 | 40 | 70 |



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)


_version_: 1