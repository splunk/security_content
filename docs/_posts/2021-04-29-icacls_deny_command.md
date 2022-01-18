---
title: "Icacls Deny Command"
excerpt: "File and Directory Permissions Modification"
categories:
  - Endpoint
last_modified_at: 2021-04-29
toc: true
toc_label: ""
tags:
  - File and Directory Permissions Modification
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies a potential adversary that changes the security permission of a specific file or directory. This technique is commonly seen in APT tradecraft or coinminer scripts. This behavior is meant to evade detection and prevent access to their component files.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-29
- **Author**: Teoderick Contreras, Splunk
- **ID**: cf8d753e-a8fe-11eb-8f58-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1222](https://attack.mitre.org/techniques/T1222/) | File and Directory Permissions Modification | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "icacls.exe" OR Processes.process_name = "cacls.exe" OR Processes.process_name = "xcacls.exe" AND Processes.process = "*/deny*" by Processes.parent_process_name Processes.process_name Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `icacls_deny_command_filter`
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)


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
Unknown. It is possible some administrative scripts use ICacls. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | Process name $process_name$ with deny argument executed by $user$ to change security permission of a specific file or directory on host $dest$ |




#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/icacls_deny_command.yml) \| *version*: **1**