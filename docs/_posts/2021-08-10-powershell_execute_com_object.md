---
title: "Powershell Execute COM Object"
excerpt: "Component Object Model Hijacking
, Event Triggered Execution
"
categories:
  - Endpoint
last_modified_at: 2021-08-10
toc: true
toc_label: ""
tags:
  - Component Object Model Hijacking
  - Event Triggered Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a COM CLSID execution through powershell. This technique was seen in several adversaries and malware like ransomware conti where it has a feature to execute command using COM Object. This technique may use by network operator at some cases but a good indicator if some application want to gain privilege escalation or bypass uac.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-08-10
- **Author**: Teoderick Contreras, Splunk
- **ID**: 65711630-f9bf-11eb-8d72-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1546.015](https://attack.mitre.org/techniques/T1546/015/) | Component Object Model Hijacking | Persistence, Privilege Escalation |

| [T1546](https://attack.mitre.org/techniques/T1546/) | Event Triggered Execution | Persistence, Privilege Escalation |

#### Search

```
`powershell` EventCode=4104 Message = "*CreateInstance([type]::GetTypeFromCLSID*" OR Message = "*CreateInstance([Type]::GetTypeFromProgID*"
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `powershell_execute_com_object_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `powershell_execute_com_object_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
network operrator may use this command.

#### Associated Analytic story
* [Malicious PowerShell](/stories/malicious_powershell)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 5.0 | 10 | 50 | A suspicious powershell script contains COM CLSID command in $Message$ with EventCode $EventCode$ in host $ComputerName$ |




#### Reference

* [https://threadreaderapp.com/thread/1423361119926816776.html](https://threadreaderapp.com/thread/1423361119926816776.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/conti_leak/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/conti_leak/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_execute_com_object.yml) \| *version*: **1**