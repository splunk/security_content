---
title: "Suspicious mshta child process"
excerpt: "Signed Binary Proxy Execution, Mshta"
categories:
  - Endpoint
last_modified_at: 2021-01-12
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

The following analytic identifies child processes spawning from  &#34;mshta.exe&#34;. The search will return the first time and last time these command-line arguments were used for these executions, as well as the target system, the user, parent process &#34;mshta.exe&#34; and its child process.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-12
- **Author**: Michael Haag, Splunk
- **ID**: 60023bb6-5500-11eb-ae93-0242ac130002


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process_name) as process_name values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=mshta.exe AND (Processes.process_name=powershell.exe OR Processes.process_name=colorcpl.exe OR Processes.process_name=msbuild.exe OR Processes.process_name=microsoft.workflow.compiler.exe OR Processes.process_name=searchprotocolhost.exe OR Processes.process_name=scrcons.exe OR Processes.process_name=cscript.exe OR Processes.process_name=wscript.exe OR Processes.process_name=powershell.exe OR Processes.process_name=cmd.exe) by Processes.dest Processes.parent_process Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_mshta_child_process_filter`
```

#### Associated Analytic Story
* [Suspicious MSHTA Activity](/stories/suspicious_mshta_activity)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.dest
* Processes.parent_process
* Processes.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Although unlikely, some legitimate applications may exhibit this behavior, triggering a false positive.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | suspicious mshta child process detected on host $dest$ by user $user$. |




#### Reference

* [https://github.com/redcanaryco/AtomicTestHarnesses](https://github.com/redcanaryco/AtomicTestHarnesses)
* [https://redcanary.com/blog/introducing-atomictestharnesses/](https://redcanary.com/blog/introducing-atomictestharnesses/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_mshta_child_process.yml) \| *version*: **1**