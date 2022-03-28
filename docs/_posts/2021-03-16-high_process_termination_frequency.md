---
title: "High Process Termination Frequency"
excerpt: "Data Encrypted for Impact
"
categories:
  - Endpoint
last_modified_at: 2021-03-16
toc: true
toc_label: ""
tags:
  - Data Encrypted for Impact
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytics are designed to indentify a high frequency of process termination on a machine which is a common behavior of ransomware malware before encrypting files. This technique is designed to avoid an exception error while accessing (docs, images, database and etc..) in the infected machine for encryption.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-03-16
- **Author**: Teoderick Contreras
- **ID**: 17cd75b2-8666-11eb-9ab4-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Impact |

#### Search

```
`sysmon` EventCode=5 
|bin _time span=3s 
|stats values(Image) as proc_terminated min(_time) as firstTime max(_time) as lastTime  count by Computer EventCode ProcessID 
| where count >= 15 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `high_process_termination_frequency_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `high_process_termination_frequency_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* EventCode
* Image
* Computer
* _time
* ProcessID


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Image (process full path of terminated process) from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
admin or user tool that can terminate multiple process.

#### Associated Analytic story
* [Clop Ransomware](/stories/clop_ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | High frequency process termination (more than 15 processes within 3s) detected on host $Computer$ |




#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/high_process_termination_frequency.yml) \| *version*: **1**