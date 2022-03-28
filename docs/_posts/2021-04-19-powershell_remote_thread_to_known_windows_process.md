---
title: "Powershell Remote Thread To Known Windows Process"
excerpt: "Process Injection
"
categories:
  - Endpoint
last_modified_at: 2021-04-19
toc: true
toc_label: ""
tags:
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

this search is designed to detect suspicious powershell process that tries to inject code and to known/critical windows process and execute it using CreateRemoteThread. This technique is seen in several malware like trickbot and offensive tooling like cobaltstrike where it load a shellcode to svchost.exe to execute reverse shell to c2 and download another payload

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-04-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: ec102cb2-a0f5-11eb-9b38-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

#### Search

```
`sysmon` EventCode = 8 process_name IN ("powershell_ise.exe", "powershell.exe") TargetImage IN ("*\\svchost.exe","*\\csrss.exe" "*\\gpupdate.exe", "*\\explorer.exe","*\\services.exe","*\\winlogon.exe","*\\smss.exe","*\\wininit.exe","*\\userinit.exe","*\\spoolsv.exe","*\\taskhost.exe") 
| stats  min(_time) as firstTime max(_time) as lastTime count by SourceImage process_name SourceProcessId SourceProcessGuid TargetImage TargetProcessId NewThreadId StartAddress Computer EventCode 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `powershell_remote_thread_to_known_windows_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `powershell_remote_thread_to_known_windows_process_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* SourceImage
* process_name
* SourceProcessId
* SourceProcessGuid
* TargetImage
* TargetProcessId
* NewThreadId
* StartAddress
* Computer
* EventCode


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, Create Remote thread from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances of create remote thread may be used.

#### Known False Positives
unknown

#### Associated Analytic story
* [Trickbot](/stories/trickbot)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A suspicious powershell process $process_name$ that tries to create a remote thread on target process $TargetImage$ with eventcode $EventCode$ in host $Computer$ |




#### Reference

* [https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/](https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_remote_thread_to_known_windows_process.yml) \| *version*: **1**