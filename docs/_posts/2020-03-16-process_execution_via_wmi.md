---
title: "Process Execution via WMI"
excerpt: "Windows Management Instrumentation"
categories:
  - Endpoint
last_modified_at: 2020-03-16
toc: true
toc_label: ""
tags:
  - Windows Management Instrumentation
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies `WmiPrvSE.exe` spawning a process. This typically occurs when a process is instantiated from a local or remote process using `wmic.exe`. During triage, review parallel processes for suspicious behavior or commands executed. Review the process and command-line spawning from `wmiprvse.exe`. Contain and remediate the endpoint as necessary.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-03-16
- **Author**: Rico Valdez, Michael Haag, Splunk
- **ID**: 24869767-8579-485d-9a4f-d9ddfd8f0cac


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=WmiPrvSE.exe by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `process_execution_via_wmi_filter` 
```

#### Associated Analytic Story
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints to populate the Endpoint data model in the Processes node. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process
* Processes.parent_process_name
* Processes.user
* Processes.dest
* Processes.process_name


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Although unlikely, administrators may use wmi to execute commands for legitimate purposes.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | A remote instance execution of wmic.exe that will spawn $parent_process_name$ in host $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/process_execution_via_wmi.yml) \| *version*: **4**