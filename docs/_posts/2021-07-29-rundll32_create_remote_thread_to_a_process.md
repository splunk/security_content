---
title: "Rundll32 Create Remote Thread To A Process"
excerpt: "Process Injection"
categories:
  - Endpoint
last_modified_at: 2021-07-29
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies the suspicious Remote Thread execution of rundll32.exe process to cmd.exe process. This technique was seen in IcedID malware to execute its malicious code in normal process for defense evasion and to steal sensitive information the the compromised host. browser process.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-29
- **Author**: Teoderick Contreras, Splunk
- **ID**: 2dbeee3a-f067-11eb-96c0-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

#### Search

```
`sysmon` EventCode=8 SourceImage = "*\\rundll32.exe" TargetImage = "*.exe" 
| stats count min(_time) as firstTime max(_time) as lastTime by SourceImage TargetImage TargetProcessId SourceProcessId StartAddress EventCode Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `rundll32_create_remote_thread_to_a_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `rundll32_create_remote_thread_to_a_process_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* SourceImage
* TargetImage
* TargetProcessId
* SourceProcessId
* StartAddress
* EventCode
* Computer


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the SourceImage, TargetImage, and EventCode executions from your endpoints related to create remote thread or injecting codes. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
unknown

#### Associated Analytic story
* [IcedID](/stories/icedid)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | rundl32 process $SourceImage$ create a remote thread to process $TargetImage$ in host $Computer$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.joesandbox.com/analysis/380662/0/html](https://www.joesandbox.com/analysis/380662/0/html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/rundll32_create_remote_thread_to_a_process.yml) \| *version*: **1**