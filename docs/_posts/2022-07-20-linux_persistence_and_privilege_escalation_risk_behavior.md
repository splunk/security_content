---
title: "Linux Persistence and Privilege Escalation Risk Behavior"
excerpt: "Abuse Elevation Control Mechanism
"
categories:
  - Endpoint
last_modified_at: 2022-07-20
toc: true
toc_label: ""
tags:
  - Abuse Elevation Control Mechanism
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Risk
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following correlation is specific to Linux persistence and privilege escalation tactics and is tied to two analytic stories and any Linux analytic tied to persistence and privilege escalation. These techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.

- **Type**: [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2022-07-20
- **Author**: Michael Haag, Splunk
- **ID**: ad5ac21b-3b1e-492c-8e19-ea5d5e8e5cf1


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Defense Evasion, Privilege Escalation |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Risk.All_Risk where (All_Risk.analyticstories IN ("Linux Privilege Escalation", "Linux Persistence Techniques") OR source = "*Linux*") All_Risk.annotations.mitre_attack.mitre_tactic IN ("persistence", "privilege-escalation") All_Risk.risk_object_type="system" by All_Risk.risk_object All_Risk.annotations.mitre_attack.mitre_tactic source All_Risk.description 
| `drop_dm_object_name(All_Risk)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| stats values(source) as detection_name values(annotations.mitre_attack.mitre_tactic) as tactics values(firstTime) as firstTime values(lastTime) as lastTime dc(annotations.mitre_attack.mitre_tactic) as distinct_tactics dc(source) as distinct_detection_name by risk_object 
| where distinct_detection_name >= 4 
| `linux_persistence_and_privilege_escalation_risk_behavior_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **linux_persistence_and_privilege_escalation_risk_behavior_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Risk.analyticstories
* All_Risk.risk_object_type
* All_Risk.risk_object
* All_Risk.annotations.mitre_attack.mitre_tactic
* source


#### How To Implement
Ensure Linux anomaly and TTP analytics are enabled. TTP may be set to Notables for point detections, anomaly should not be notables but risk generators. The correlation relies on more than x amount of distict detection names generated before generating a notable. Modify the value as needed. Default value is set to 4. This value may need to be increased based on activity in your environment.

#### Known False Positives
False positives will be present based on many factors. Tune the correlation as needed to reduce too many triggers.

#### Associated Analytic story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | Privilege escalation and persistence behaviors have been identified on $risk_object$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/linux_risk/linuxrisk.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/linux_risk/linuxrisk.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_persistence_and_privilege_escalation_risk_behavior.yml) \| *version*: **1**