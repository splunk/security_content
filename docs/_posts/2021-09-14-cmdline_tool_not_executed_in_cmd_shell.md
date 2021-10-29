---
title: "Cmdline Tool Not Executed In CMD Shell"
excerpt: "Command and Scripting Interpreter, JavaScript"
categories:
  - Endpoint
last_modified_at: 2021-09-14
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - JavaScript
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious parent process execution of commandline tool not in shell commandline. This technique was seen in FIN7 JSSLoader .net compile payload where it run ipconfig.exe and systeminfo.exe using .net application. This event cause some good TTP since those tool are commonly run in commandline not by another application. This TTP is a good indicator for application gather host information either an attacker or an automated tool made by admin.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: 6c3f7dd8-153c-11ec-ac2d-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |



| [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | JavaScript | Execution |





#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where  (Processes.process_name = "ipconfig.exe" OR Processes.process_name = "systeminfo.exe") AND NOT (Processes.parent_process_name = "cmd.exe" OR Processes.parent_process_name = "powershell*" OR Processes.parent_process_name = "explorer.exe") by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process_id Processes.process Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `cmdline_tool_not_executed_in_cmd_shell_filter`
```

#### Associated Analytic Story
* [FIN7](/stories/fin7)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process_id
* Processes.process
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
network operator or admin may create this type of tool to gather host information


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | parent process name $parent_process_name$ with child process $process_name$ to execute commandline tool in $dest$ |




#### Reference

* [https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)
* [https://attack.mitre.org/groups/G0046/](https://attack.mitre.org/groups/G0046/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/jssloader/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/jssloader/sysmon.log)


[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/cmdline_tool_not_executed_in_cmd_shell.yml) \| *version*: **1**