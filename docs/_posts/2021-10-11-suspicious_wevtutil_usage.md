---
title: "Suspicious wevtutil Usage"
excerpt: "Clear Windows Event Logs, Indicator Removal on Host"
categories:
  - Endpoint
last_modified_at: 2021-10-11
toc: true
toc_label: ""
tags:
  - Clear Windows Event Logs
  - Defense Evasion
  - Indicator Removal on Host
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The wevtutil.exe application is the windows event log utility. This searches for wevtutil.exe with parameters for clearing the application, security, setup, trace or system event logs.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-11
- **Author**: David Dorsey, Michael Haag, Splunk
- **ID**: 2827c0fd-e1be-4868-ae25-59d28e0f9d4f


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | Defense Evasion |

| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=wevtutil.exe Processes.process IN ("* cl *", "*clear-log*") (Processes.process="*System*" OR Processes.process="*Security*" OR Processes.process="*Setup*" OR Processes.process="*Application*" OR Processes.process="*trace*") by Processes.process_name Processes.parent_process_name Processes.dest Processes.user
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `suspicious_wevtutil_usage_filter`
```

#### Associated Analytic Story
* [Windows Log Manipulation](/stories/windows_log_manipulation)
* [Ransomware](/stories/ransomware)
* [Clop Ransomware](/stories/clop_ransomware)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process
* Processes.process_name
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
The wevtutil.exe application is a legitimate Windows event log utility. Administrators may use it to manage Windows event logs.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 28.0 | 40 | 70 | Wevtutil.exe being used to clear Event Logs on $dest$ by $user$ |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_wevtutil_usage.yml) \| *version*: **4**