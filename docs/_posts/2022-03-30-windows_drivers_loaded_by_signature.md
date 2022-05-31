---
title: "Windows Drivers Loaded by Signature"
excerpt: "Rootkit
, Exploitation for Privilege Escalation
"
categories:
  - Endpoint
last_modified_at: 2022-03-30
toc: true
toc_label: ""
tags:
  - Rootkit
  - Exploitation for Privilege Escalation
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic assists with viewing all drivers being loaded by using Sysmon EventCode 6 (Driver Load). Sysmon provides some simple fields to assist with identifying suspicious drivers. Use this analytic to look at prevalence of driver (count), path of driver, signature status and hash. Review these fields with scrutiny until the ability to prove the driver is legitimate and has a purpose in the environment.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-03-30
- **Author**: Michael Haag, Splunk
- **ID**: d2d4af6a-6c2b-4d79-80c5-fc2cf12a2f68


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1014](https://attack.mitre.org/techniques/T1014/) | Rootkit | Defense Evasion |

| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation |

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
`sysmon` EventCode=6 
| stats min(_time) as firstTime max(_time) as lastTime values(ImageLoaded) count by Computer Signed Signature service_signature_verified service_signature_exists Hashes 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_drivers_loaded_by_signature_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

> :information_source:
> **windows_drivers_loaded_by_signature_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ImageLoaded
* Computer
* Signed
* Signature
* service_signature_verified
* service_signature_exists
* Hashes


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have the latest version of the Sysmon TA. Most EDR products provide the ability to review driver loads, or module loads, and using a query as such help with hunting for malicious drivers.

#### Known False Positives
This analytic is meant to assist with identifying drivers loaded in the environment and not to be setup for notables off the bat.

#### Associated Analytic story
* [Windows Drivers](/stories/windows_drivers)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | A driver has loaded on $Computer$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/](https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/)
* [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)
* [https://www.fuzzysecurity.com/tutorials/28.html](https://www.fuzzysecurity.com/tutorials/28.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1014/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1014/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_drivers_loaded_by_signature.yml) \| *version*: **1**