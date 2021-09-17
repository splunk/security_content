---
title: "Unload Sysmon Filter Driver"
excerpt: "Disable or Modify Tools"
categories:
  - Endpoint
last_modified_at: 2020-07-22
toc: true
tags:
  - TTP
  - T1562.001
  - Disable or Modify Tools
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---

#### Description

Attackers often disable security tools to avoid detection. This search looks for the usage of process `fltMC.exe` to unload a Sysmon Driver that will stop sysmon from collecting the data.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-22
- **Author**: Bhavin Patel, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime values(Processes.process) as process max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=fltMC.exe AND Processes.process=*unload* AND Processes.process=*SysmonDrv*  by Processes.process_name Processes.process_id Processes.parent_process_name Processes.process Processes.dest Processes.user 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
|`unload_sysmon_filter_driver_filter`
| table firstTime lastTime dest user count process_name process_id parent_process_name process
```

#### Associated Analytic Story
* [Disabling Security Tools](_stories/disabling_security_tools)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model. This search is also shipped with `unload_sysmon_filter_driver_filter` macro, update this macro to filter out false positives.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives




#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 45.0 | 50 | 90 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/windows-sysmon.log)


_version_: 3