---
title: "Windows Driver Load Non-Standard Path"
excerpt: "Rootkit
"
categories:
  - Endpoint
last_modified_at: 2022-04-04
toc: true
toc_label: ""
tags:
  - Rootkit
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic uses Windows EventCode 7045 to identify new Kernel Mode Drivers being loaded in Windows from a non-standard path. Note that, adversaries may move malicious or vulnerable drivers into these paths and load up. The idea is that this analytic provides visibility into drivers loading in non-standard file paths.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-04
- **Author**: Michael Haag, Splunk
- **ID**: 9216ef3d-066a-4958-8f27-c84589465e62


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1014](https://attack.mitre.org/techniques/T1014/) | Rootkit | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Installation


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
`wineventlog_system` EventCode=7045 Service_Type="kernel mode driver" NOT (Service_File_Name IN ("*\\Windows\\*", "*\\Program File*", "*\\systemroot\\*","%SystemRoot%*", "system32\*")) 
| stats count min(_time) as firstTime max(_time) as lastTime by ComputerName EventCode Service_File_Name Service_Name Service_Start_Type Service_Type 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_driver_load_non_standard_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_system](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_system.yml)

> :information_source:
> **windows_driver_load_non-standard_path_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* ComputerName
* EventCode
* Service_File_Name
* Service_Name
* Service_Start_Type
* Service_Type


#### How To Implement
To implement this analytic, the Windows EventCode 7045 will need to be logged. The Windows TA for Splunk is also recommended.

#### Known False Positives
False positives may be present based on legitimate third party applications needing to install drivers. Filter, or allow list known good drivers consistently being installed in these paths.

#### Associated Analytic story
* [Windows Drivers](/stories/windows_drivers)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | A kernel mode driver was loaded from a non-standard path on $ComputerName$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/](https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/)
* [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)
* [https://www.fuzzysecurity.com/tutorials/28.html](https://www.fuzzysecurity.com/tutorials/28.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/7045_kerneldrivers.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/7045_kerneldrivers.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_driver_load_non_standard_path.yml) \| *version*: **1**