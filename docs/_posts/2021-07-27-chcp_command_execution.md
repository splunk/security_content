---
title: "CHCP Command Execution"
excerpt: "Command and Scripting Interpreter"
categories:
  - Endpoint
last_modified_at: 2021-07-27
toc: true
tags:
  - TTP
  - T1059
  - Command and Scripting Interpreter
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Reconnaissance
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect execution of chcp.exe application. this utility is used to change the active code page of the console. This technique was seen in icedid malware to know the locale region/language/country of the compromise host.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-27
- **Author**: Teoderick Contreras, Splunk
- **ID**: 21d236ec-eec1-11eb-b23e-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |



#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=chcp.com Processes.parent_process_name = cmd.exe Processes.parent_process=*/c* by  Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.process_id Processes.parent_process_id Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `chcp_command_execution_filter`
```

#### Associated Analytic Story
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed chcp.com may be used.

#### Required field
* _time
* process_name
* process
* parent_process_name
* parent_process
* process_id
* parent_process_id
* dest
* user


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
other tools or script may used this to change code page to UTF-* or others



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | parent process $parent_process_name$ spawning chcp process $process_name$ with parent command line $parent_process$ |



#### Reference

* [https://ss64.com/nt/chcp.html](https://ss64.com/nt/chcp.html)
* [https://twitter.com/tccontre18/status/1419941156633329665?s=20](https://twitter.com/tccontre18/status/1419941156633329665?s=20)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/chcp_command_execution.yml) \| *version*: **1**