---
title: "Windows KrbRelayUp Service Creation"
excerpt: "Windows Service
"
categories:
  - Endpoint
last_modified_at: 2022-05-02
toc: true
toc_label: ""
tags:
  - Windows Service
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the default service name created by KrbRelayUp. Defenders should be aware that attackers could change the hardcoded service name of the KrbRelayUp tool and bypass this detection.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-05-02
- **Author**: Michael Haag, Splunk
- **ID**: e40ef542-8241-4419-9af4-6324582ea60a


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |

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
`wineventlog_system` EventCode=7045 Service_Name IN ("KrbSCM") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Service_File_Name Service_Name Service_Start_Type Service_Type 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_krbrelayup_service_creation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_system](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_system.yml)

> :information_source:
> **windows_krbrelayup_service_creation_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Service_File_Name
* Service_Name
* Service_Start_Type
* Service_Type


#### How To Implement
To successfully implement this search, you need to be ingesting Windows System Event Logs with 7045 EventCode enabled. The Windows TA is also required.

#### Known False Positives
False positives should be limited as this is specific to KrbRelayUp based attack. Filter as needed.

#### Associated Analytic story
* [Local Privilege Escalation With KrbRelayUp](/stories/local_privilege_escalation_with_krbrelayup)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A service was created on $dest$, related to KrbRelayUp. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_krbrelayup_service_creation.yml) \| *version*: **1**