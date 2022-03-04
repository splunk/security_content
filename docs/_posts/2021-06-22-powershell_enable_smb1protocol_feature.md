---
title: "Powershell Enable SMB1Protocol Feature"
excerpt: "Obfuscated Files or Information
, Indicator Removal from Tools
"
categories:
  - Endpoint
last_modified_at: 2021-06-22
toc: true
toc_label: ""
tags:

  - Obfuscated Files or Information
  - Indicator Removal from Tools
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious enabling of smb1protocol through "powershell.exe". This technique was seen in some ransomware (like reddot) where it enable smb share to do the lateral movement and encrypt other files within the compromise network system.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-22
- **Author**: Teoderick Contreras, Splunk
- **ID**: afed80b2-d34b-11eb-a952-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Defense Evasion |

| [T1027.005](https://attack.mitre.org/techniques/T1027/005/) | Indicator Removal from Tools | Defense Evasion |

#### Search

```
`powershell` EventCode=4104 Message = "*Enable-WindowsOptionalFeature*" Message = "*SMB1Protocol*" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `powershell_enable_smb1protocol_feature_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)

Note that `powershell_enable_smb1protocol_feature_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the powershell logs  from your endpoints. make sure you enable needed registry to monitor this event.

#### Known False Positives
network operator may enable or disable this windows feature.

#### Associated Analytic story
* [Malicious PowerShell](/stories/malicious_powershell)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | Powershell Enable SMB1Protocol Feature |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/](https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_enable_smb1protocol_feature.yml) \| *version*: **1**