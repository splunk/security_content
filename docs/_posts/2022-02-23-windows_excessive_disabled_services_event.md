---
title: "Windows Excessive Disabled Services Event"
excerpt: "Disable or Modify Tools
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2022-02-23
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify suspicious excessive number of system events of services that was modified from start to disabled. This technique is seen where the adversary attempts to disable security app services, other malware services oer serve as an destructive impact to complete the objective on the compromised system. One good example for this scenario is Olympic destroyer where it disable all active services in the compromised host as part of its destructive impact and defense evasion.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-02-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: c3f85976-94a5-11ec-9a58-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`wineventlog_system` EventCode=7040 Message = "*service was changed from demand start to disabled." 
| stats count values(Message) as MessageList dc(Message) as MessageCount min(_time) as firstTime max(_time) as lastTime by ComputerName EventCode  User Sid 
| where MessageCount >=10 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_excessive_disabled_services_event_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_system](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_system.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **windows_excessive_disabled_services_event_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Unknown

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | Service was disabled in $Computer$ |


#### Reference

* [https://blog.talosintelligence.com/2018/02/olympic-destroyer.html](https://blog.talosintelligence.com/2018/02/olympic-destroyer.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/olympic_destroyer/system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/olympic_destroyer/system.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_excessive_disabled_services_event.yml) \| *version*: **1**