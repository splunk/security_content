---
title: "Living Off The Land"
excerpt: "Ingress Tool Transfer
, Exploit Public-Facing Application
, Command and Scripting Interpreter
"
categories:
  - Endpoint
last_modified_at: 2022-07-08
toc: true
toc_label: ""
tags:
  - Ingress Tool Transfer
  - Exploit Public-Facing Application
  - Command and Scripting Interpreter
  - Command And Control
  - Initial Access
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Risk
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following correlation identifies a distinct amount of analytics associated with the Living Off The Land analytic story that identify potentially suspicious behavior.

- **Type**: [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2022-07-08
- **Author**: Michael Haag, Splunk
- **ID**: 1be30d80-3a39-4df9-9102-64a467b24abc


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance
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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Risk.All_Risk where All_Risk.analyticstories="Living Off The Land" All_Risk.risk_object_type="system" by All_Risk.risk_object All_Risk.annotations.mitre_attack.mitre_tactic source 
| `drop_dm_object_name(All_Risk)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| stats  values(source) as detection_name values(annotations.mitre_attack.mitre_tactic) as tactics values(firstTime) as firstTime values(lastTime) as lastTime dc(annotations.mitre_attack.mitre_tactic) as distinct_tactics dc(source) as distinct_detection_name by risk_object 
| where distinct_detection_name >= 2 
| `living_off_the_land_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **living_off_the_land_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Risk.analyticstories
* All_Risk.risk_object_type
* All_Risk.risk_object
* All_Risk.annotations.mitre_attack.mitre_tactic
* source


#### How To Implement
To implement this correlation search a user needs to enable all detections in the Living Off The Land Analytic Story and confirm it is generating risk events. A simple search `index=risk analyticstories="Living Off The Land"` should contain events.

#### Known False Positives
There are no known false positive for this search, but it could contain false positives as multiple detections can trigger and not have successful exploitation. Modify the static value distinct_detection_name to a higher value. It is also required to tune analytics that are also tagged to ensure volume is never too much.

#### Associated Analytic story
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 90 | 70 | An increase of Living Off The Land behavior has been detected on $affected_systems$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.splunk.com/en_us/blog/security/living-off-the-land-threat-research-february-2022-release.html](https://www.splunk.com/en_us/blog/security/living-off-the-land-threat-research-february-2022-release.html)
* [https://research.splunk.com/stories/living_off_the_land/](https://research.splunk.com/stories/living_off_the_land/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1218/living_off_the_land/lolbinrisk.log](https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1218/living_off_the_land/lolbinrisk.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/living_off_the_land.yml) \| *version*: **1**