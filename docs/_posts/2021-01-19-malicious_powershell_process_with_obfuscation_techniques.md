---
title: "Malicious PowerShell Process With Obfuscation Techniques"
excerpt: "PowerShell"
categories:
  - Endpoint
last_modified_at: 2021-01-19
toc: true
tags:
  - TTP
  - T1059.001
  - PowerShell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Command and Control
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for PowerShell processes launched with arguments that have characters indicative of obfuscation on the command-line.

- **ID**: cde75cf6-3c7a-4dd6-af01-27cdb4511fd4
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-19
- **Author**: David Dorsey, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |


#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=powershell.exe by Processes.user Processes.process_name Processes.parent_process_name Processes.dest Processes.process 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval num_obfuscation = (mvcount(split(process,"`"))-1) + (mvcount(split(process, "^"))-1) + (mvcount(split(process, "'"))-1) 
| `malicious_powershell_process_with_obfuscation_techniques_filter` 
| search num_obfuscation > 10 
```

#### Associated Analytic Story
* [Malicious PowerShell](/stories/malicious_powershell)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process
* Processes.parent_process
* Processes.process_name
* Processes.user
* Processes.parent_process_name
* Processes.dest


#### Kill Chain Phase
* Command and Control
* Actions on Objectives


#### Known False Positives
These characters might be legitimately on the command-line, but it is not common.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | Powershell.exe running with potential obfuscated arguments on $dest$ |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/obfuscated_powershell/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/obfuscated_powershell/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/malicious_powershell_process_with_obfuscation_techniques.yml) \| *version*: **4**