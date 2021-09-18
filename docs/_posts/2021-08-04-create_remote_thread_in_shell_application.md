---
title: "Create Remote Thread In Shell Application"
excerpt: "Process Injection"
categories:
  - Endpoint
last_modified_at: 2021-08-04
toc: true
tags:
  - TTP
  - T1055
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

This search is to detect suspicious process injection in command shell. This technique was seen in IcedID where it execute cmd.exe process to inject its shellcode as part of its execution as banking trojan. It is really uncommon to have a create remote thread execution in the following application.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-04
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |


#### Search

```
`sysmon` EventCode=8 TargetImage IN ("*\\cmd.exe", "*\\powershell*") 
| stats count min(_time) as firstTime max(_time) as lastTime by  TargetImage TargetProcessId SourceProcessId  EventCode StartAddress SourceImage Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `create_remote_thread_in_shell_application_filter`
```

#### Associated Analytic Story
* [IcedID](_stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* SourceImage
* TargetImage
* TargetProcessId
* SourceProcessId
* StartAddress
* EventCode
* Computer


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 70.0 | 70 | 100 |



#### Reference

* [https://thedfirreport.com/2021/07/19/icedid-and-cobalt-strike-vs-antivirus/](https://thedfirreport.com/2021/07/19/icedid-and-cobalt-strike-vs-antivirus/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log)


_version_: 1