---
title: "Windows Gather Victim Host Information Camera"
excerpt: "Hardware
, Gather Victim Host Information
"
categories:
  - Endpoint
last_modified_at: 2022-07-28
toc: true
toc_label: ""
tags:
  - Hardware
  - Gather Victim Host Information
  - Reconnaissance
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic detects a powershell script that enumerate camera mounted to the targeted host. This technique was seen in DCRat malware, where it runs a powershell command to look for camera information that will be pass on to its C2 server. This anomaly detection can be a good pivot to check who and why this enumeration is needed and what parent process execute this powershell script command.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-28
- **Author**: Teoderick Contreras, Splunk
- **ID**: e4df4676-ea41-4397-b160-3ee0140dc332


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1592.001](https://attack.mitre.org/techniques/T1592/001/) | Hardware | Reconnaissance |

| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | Reconnaissance |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


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
`powershell` EventCode=4104 ScriptBlockText= "* Win32_PnPEntity *" ScriptBlockText= "*SELECT*" ScriptBlockText= "*WHERE*" ScriptBlockText = "*PNPClass*" ScriptBlockText IN ("*Image*", "*Camera*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode ScriptBlockText Computer UserID 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_gather_victim_host_information_camera_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)

> :information_source:
> **windows_gather_victim_host_information_camera_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ScriptBlockText
* Computer
* EventCode


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
Administrators may execute this powershell command to get hardware information related to camera.

#### Associated Analytic story
* [DarkCrystal RAT](/stories/darkcrystal_rat)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | powershell script $ScriptBlockText$ to enumerate camera in $Computer$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://cert.gov.ua/article/405538](https://cert.gov.ua/article/405538)
* [https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat](https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat)
* [https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor](https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_enum_camera/windows-powershell-xml.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_enum_camera/windows-powershell-xml.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_gather_victim_host_information_camera.yml) \| *version*: **1**