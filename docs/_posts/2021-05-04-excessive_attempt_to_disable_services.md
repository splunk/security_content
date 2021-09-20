---
title: "Excessive Attempt To Disable Services"
excerpt: "Service Stop"
categories:
  - Endpoint
last_modified_at: 2021-05-04
toc: true
tags:
  - Anomaly
  - T1489
  - Service Stop
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

This analytic will identify suspicious series of command-line to disable several services. This technique is seen where the adversary attempts to disable security app services or other malware services to complete the objective on the compromised system.

- **ID**: 8fa2a0f0-acd9-11eb-8994-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-04
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1489](https://attack.mitre.org/techniques/T1489/) | Service Stop | Impact |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime  from datamodel=Endpoint.Processes where   Processes.process_name = "sc.exe" AND Processes.process="*config*" OR Processes.process="*Disabled*" by Processes.process_name Processes.parent_process_name Processes.dest Processes.user _time span=1m 
| where count >=5 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_attempt_to_disable_services_filter`
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed sc.exe may be used.

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
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 80.0 | 80 | 100 |



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)


_version_: 1