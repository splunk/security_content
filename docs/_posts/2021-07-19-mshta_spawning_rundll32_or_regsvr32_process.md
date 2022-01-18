---
title: "Mshta spawning Rundll32 OR Regsvr32 Process"
excerpt: "Signed Binary Proxy Execution, Mshta"
categories:
  - Endpoint
last_modified_at: 2021-07-19
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Mshta
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
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


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name = "mshta.exe"  `process_rundll32` OR `process_regsvr32` by Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.process_guid Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `mshta_spawning_rundll32_or_regsvr32_process_filter`
```

#### Associated Analytic Story
* [Trickbot](/stories/trickbot)
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/mshta_spawning_rundll32_or_regsvr32_process.yml) \| *version*: **2**