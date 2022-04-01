---
title: "Windows Service Created With Suspicious Service Path"
excerpt: "System Services
, Service Execution
"
categories:
  - Endpoint
last_modified_at: 2021-11-22
toc: true
toc_label: ""
tags:
  - System Services
  - Service Execution
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytc uses Windows Event Id 7045, `New Service Was Installed`, to identify the creation of a Windows Service where the service binary path path is located in a non-common Service folder in Windows. Red Teams and adversaries alike may create malicious Services for lateral movement or remote code execution as well as persistence and execution. The Clop ransomware has also been seen in the wild abusing Windows services.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-11-22
- **Author**: Teoderick Contreras, Mauricio Velazco, Splunk
- **ID**: 429141be-8311-11eb-adb6-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1569](https://attack.mitre.org/techniques/T1569/) | System Services | Execution |

| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | Execution |

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



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
 `wineventlog_system` EventCode=7045  Service_File_Name = "*\.exe" NOT (Service_File_Name IN ("C:\\Windows\\*", "C:\\Program File*", "C:\\Programdata\\*", "%systemroot%\\*")) 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Service_File_Name Service_Name Service_Start_Type Service_Type 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_service_created_with_suspicious_service_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_system](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_system.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **windows_service_created_with_suspicious_service_path_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* EventCode
* Service_File_Name
* Service_Type
* _time
* Service_Name
* Service_Start_Type


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Service name, Service File Name Service Start type, and Service Type from your endpoints.

#### Known False Positives
Legitimate applications may install services with uncommon services paths.

#### Associated Analytic story
* [Clop Ransomware](/stories/clop_ransomware)
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A service $Service_File_Name$ was created from a non-standard path using $Service_Name$ |


#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-system.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_service_created_with_suspicious_service_path.yml) \| *version*: **2**