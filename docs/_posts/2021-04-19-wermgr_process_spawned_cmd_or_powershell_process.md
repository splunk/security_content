---
title: "Wermgr Process Spawned CMD Or Powershell Process"
excerpt: "Command and Scripting Interpreter"
categories:
  - Endpoint
last_modified_at: 2021-04-19
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
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is designed to detect suspicious cmd and powershell process spawned by wermgr.exe process. This suspicious behavior are commonly seen in code injection technique technique like trickbot to execute a shellcode, dll modules to run malicious behavior.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: e8fc95bc-a107-11eb-a978-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |



#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as cmdline min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name = "wermgr.exe" `process_cmd` OR `process_powershell` by Processes.parent_process_name  Processes.original_file_name Processes.parent_process_id  Processes.process_name Processes.process Processes.process_id Processes.process_guid Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wermgr_process_spawned_cmd_or_powershell_process_filter`
```

#### Associated Analytic Story
* [Trickbot](/stories/trickbot)


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
unknown



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | Wermgr.exe spawning suspicious processes on $dest$ |



#### Reference

* [https://labs.vipre.com/trickbot-and-its-modules/](https://labs.vipre.com/trickbot-and-its-modules/)
* [https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html](https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wermgr_process_spawned_cmd_or_powershell_process.yml) \| *version*: **2**