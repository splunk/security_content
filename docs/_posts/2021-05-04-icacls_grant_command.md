---
title: "ICACLS Grant Command"
excerpt: "File and Directory Permissions Modification"
categories:
  - Endpoint
last_modified_at: 2021-05-04
toc: true
tags:
  - TTP
  - T1222
  - File and Directory Permissions Modification
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

#### Description

This analytic identifies potential adversaries that modify the security permission of a specific file or directory. This technique is commonly seen in APT tradecraft and coinminer scripts to evade detections and restrict access to their component files.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-04
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1222](https://attack.mitre.org/techniques/T1222/) | File and Directory Permissions Modification | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "icacls.exe" OR Processes.process_name = "cacls.exe" OR Processes.process_name = "xcacls.exe" AND Processes.process = "*/grant*" by Processes.parent_process_name Processes.process_name Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `icacls_grant_command_filter`
```

#### Associated Analytic Story
* [XMRig](_stories/xmrig)
* [Ransomware](_stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed icacls.exe may be used.

#### Required field
* _time
* Processes.parent_process_name
* Processes.process_name
* Processes.dest
* Processes.user
* Processes.process_id
* Processes.process


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Unknown. Filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 49.0 | 70 | 70 |



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)


_version_: 1