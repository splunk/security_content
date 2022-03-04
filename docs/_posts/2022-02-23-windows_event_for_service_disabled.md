---
title: "Windows Event For Service Disabled"
excerpt: "Disable or Modify Tools, Impair Defenses"
categories:
  - Endpoint
last_modified_at: 2022-02-23
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Defense Evasion
  - Impair Defenses
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify suspicious system event of services that was modified from start to disabled. This technique is seen where the adversary attempts to disable security app services, other malware services to evade the defense systems on the compromised host

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-02-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9c2620a8-94a1-11ec-b40c-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```
`wineventlog_system` EventCode=7040 Message = "*service was changed from demand start to disabled." 
| stats count min(_time) as firstTime max(_time) as lastTime by ComputerName EventCode Message User Sid 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_event_for_service_disabled_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_system](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_system.yml)

Note that `windows_event_for_service_disabled_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ComputerName
* EventCode
* Message
* User
* Sid


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Service name, Service File Name Service Start type, and Service Type from your endpoints.

#### Known False Positives
Windows service update may cause this event. In that scenario, filtering is needed.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | Service was disabled on $Computer$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://blog.talosintelligence.com/2018/02/olympic-destroyer.html](https://blog.talosintelligence.com/2018/02/olympic-destroyer.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/olympic_destroyer/system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/olympic_destroyer/system.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_event_for_service_disabled.yml) \| *version*: **1**