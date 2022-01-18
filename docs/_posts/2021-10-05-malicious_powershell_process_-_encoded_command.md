---
title: "Malicious PowerShell Process - Encoded Command"
excerpt: "Obfuscated Files or Information"
categories:
  - Endpoint
last_modified_at: 2021-10-05
toc: true
toc_label: ""
tags:
  - Obfuscated Files or Information
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of the EncodedCommand PowerShell parameter. This is typically used by Administrators to run complex scripts, but commonly used by adversaries to hide their code. \
The analytic identifies all variations of EncodedCommand, as PowerShell allows the ability to shorten the parameter. For example enc, enco, encod and so forth. In addition, through our research it was identified that PowerShell will interpret different command switch types beyond the hyphen. We have added endash, emdash, horizontal bar, and forward slash. \
During triage, review parallel events to determine legitimacy. Tune as needed based on admin scripts in use. \
Alternatively, may use regex per matching here https://regexr.com/662ov.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-05
- **Author**: David Dorsey, Michael Haag, Splunk
- **ID**: c4db14d9-7909-48b4-a054-aa14d89dbb19


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_powershell` by Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.original_file_name Processes.dest Processes.process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| where match(process,"(?i)[\-
|\/
|–
|—
|―]e(nc*o*d*e*d*c*o*m*m*a*n*d*)*\s+[^-]") 
| `malicious_powershell_process___encoded_command_filter`
```

#### Associated Analytic Story
* [Malicious PowerShell](/stories/malicious_powershell)
* [NOBELIUM Group](/stories/nobelium_group)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

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

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Powershell.exe running potentially malicious encodede commands on $dest$ |




#### Reference

* [https://regexr.com/662ov](https://regexr.com/662ov)
* [https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/TestHarnesses/T1059.001_PowerShell/OutPowerShellCommandLineParameter.ps1](https://github.com/redcanaryco/AtomicTestHarnesses/blob/master/TestHarnesses/T1059.001_PowerShell/OutPowerShellCommandLineParameter.ps1)
* [https://ss64.com/ps/powershell.html](https://ss64.com/ps/powershell.html)
* [https://twitter.com/M_haggis/status/1440758396534214658?s=20](https://twitter.com/M_haggis/status/1440758396534214658?s=20)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/malicious_powershell_process_-_encoded_command.yml) \| *version*: **6**