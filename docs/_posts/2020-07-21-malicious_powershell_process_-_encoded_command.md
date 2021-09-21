---
title: "Malicious PowerShell Process - Encoded Command"
excerpt: "Obfuscated Files or Information"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
tags:
  - Hunting
  - T1027
  - Obfuscated Files or Information
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Command and Control
  - Actions on Objectives
---



#### Description

This search looks for PowerShell processes that have encoded the script within the command-line. Malware has been seen using this parameter, as it obfuscates the code and makes it relatively easy to pass a script on the command-line.

- **ID**: c4db14d9-7909-48b4-a054-aa14d89dbb19
- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = powershell.exe (Processes.process=*-EncodedCommand* OR Processes.process=*-enc*) by Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.dest Processes.process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `malicious_powershell_process___encoded_command_filter`
```

#### Associated Analytic Story
* [Malicious PowerShell](/stories/malicious_powershell)
* [NOBELIUM Group](/stories/nobelium_group)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.user
* Processes.parent_process_name
* Processes.dest
* Processes.process_id


#### Kill Chain Phase
* Command and Control
* Actions on Objectives


#### Known False Positives
System administrators may use this option, but it&#39;s not common.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 35.0 | 70 | 50 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/malicious_powershell_process_-_encoded_command.yml) \| *version*: **4**