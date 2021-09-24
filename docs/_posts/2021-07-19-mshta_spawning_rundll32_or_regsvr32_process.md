---
title: "Mshta spawning Rundll32 OR Regsvr32 Process"
excerpt: "Mshta"
categories:
  - Endpoint
last_modified_at: 2021-07-19
toc: true
tags:
  - TTP
  - T1218.005
  - Mshta
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious mshta.exe process that spawn rundll32 or regsvr32 child process. This technique was seen in several malware nowadays like trickbot to load its initial .dll stage loader to execute and download the the actual trickbot payload.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: 4aa5d062-e893-11eb-9eb2-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name = "mshta.exe"  (Processes.process_name=rundll32.exe OR Processes.process_name=regsvr32.exe) by Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.process_guid Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `mshta_spawning_rundll32_or_regsvr32_process_filter`
```

#### Associated Analytic Story
* [Trickbot](/stories/trickbot)
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed mshta.exe may be used.

#### Required field
* _time
* parent_process
* process_name
* process
* process_id
* process_guid


#### Kill Chain Phase
* Exploitation


#### Known False Positives
limitted. this anomaly behavior is not commonly seen in clean host.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | a mshta parent process $parent_process_name$ spawn child process $process_name$ in host $dest$ |



#### Reference

* [https://twitter.com/cyb3rops/status/1416050325870587910?s=21](https://twitter.com/cyb3rops/status/1416050325870587910?s=21)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/spear_phish/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/spear_phish/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/mshta_spawning_rundll32_or_regsvr32_process.yml) \| *version*: **1**