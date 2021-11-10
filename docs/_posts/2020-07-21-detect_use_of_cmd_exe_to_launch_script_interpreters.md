---
title: "Detect Use of cmd exe to Launch Script Interpreters"
excerpt: "Command and Scripting Interpreter, Windows Command Shell"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - Windows Command Shell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the execution of the cscript.exe or wscript.exe processes, with a parent of cmd.exe. The search will return the count, the first and last time this execution was seen on a machine, the user, and the destination of the machine

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Mauricio Velazco, Splunk
- **ID**: b89919ed-fe5f-492c-b139-95dbb162039e


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="cmd.exe" (Processes.process_name=cscript.exe OR Processes.process_name =wscript.exe) by Processes.parent_process Processes.process_name Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
| `detect_use_of_cmd_exe_to_launch_script_interpreters_filter`
```

#### Associated Analytic Story
* [Emotet Malware  DHS Report TA18-201A ](/stories/emotet_malware__dhs_report_ta18-201a_)
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)


#### How To Implement
To successfully implement this search, you must be ingesting data that records process activity from your hosts to populate the endpoint data model in the processes node. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Processes.process
* Processes.parent_process_name
* Processes.process_name
* Processes.parent_process
* Processes.user
* Processes.dest


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Some legitimate applications may exhibit this behavior.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | cmd.exe launching script interpreters on $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/cmd_spawns_cscript/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/cmd_spawns_cscript/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_use_of_cmd_exe_to_launch_script_interpreters.yml) \| *version*: **4**