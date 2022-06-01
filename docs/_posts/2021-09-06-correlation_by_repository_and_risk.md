---
title: "Correlation by Repository and Risk"
excerpt: "Malicious Image
, User Execution
"
categories:
  - Cloud
last_modified_at: 2021-09-06
toc: true
toc_label: ""
tags:
  - Malicious Image
  - User Execution
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search correlations detections by repository and risk_score

- **Type**: [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-09-06
- **Author**: Patrick Bareiss, Splunk
- **ID**: 8da9fdd9-6a1b-4ae0-8a34-8c25e6be9687


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1204.003](https://attack.mitre.org/techniques/T1204/003/) | Malicious Image | Execution |

| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.DS
* PR.AC
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 13



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```
`signals` 
| fillnull 
| stats sum(risk_score) as risk_score values(source) as signals values(user) as user by repository 
| sort - risk_score 
| where risk_score > 80 
| `correlation_by_repository_and_risk_filter`
```

#### Macros
The SPL above uses the following Macros:
* [signals](https://github.com/splunk/security_content/blob/develop/macros/signals.yml)

> :information_source:
> **correlation_by_repository_and_risk_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
For Dev Sec Ops POC

#### Known False Positives
unknown

#### Associated Analytic story
* [Dev Sec Ops](/stories/dev_sec_ops)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | Correlation triggered for user $user$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/correlation_by_repository_and_risk.yml) \| *version*: **1**