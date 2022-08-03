---
title: "Splunk User Enumeration Attempt"
excerpt: "Valid Accounts
"
categories:
  - Application
last_modified_at: 2022-04-29
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-33845
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

On May 3rd, 2022, Splunk published a security advisory for  username enumeration stemming from verbose login failure messages present on some REST endpoints. This detection will alert on attempted exploitation in patched versions of Splunk as well as actual exploitation in unpatched version of Splunk.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-04-29
- **Author**: Lou Stella, Splunk
- **ID**: 25625cb4-1c4d-4463-b0f9-7cb462699cde


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

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
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-33845](https://nvd.nist.gov/vuln/detail/CVE-2021-33845) | The Splunk Enterprise REST API allows enumeration of usernames via the lockout error message. The potential vulnerability impacts Splunk Enterprise instances before 8.1.7 when configured to repress verbose login errors. | 5.0 |



</div>
</details>

#### Search 

```
 `splunkd_failed_auths` 
| stats count(user) as auths by user, src 
| where auths>5 
| stats values(user) as "Users", sum(auths) as TotalFailedAuths by src 
| `splunk_user_enumeration_attempt_filter`
```

#### Macros
The SPL above uses the following Macros:
* [splunkd_failed_auths](https://github.com/splunk/security_content/blob/develop/macros/splunkd_failed_auths.yml)

> :information_source:
> **splunk_user_enumeration_attempt_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* user
* src
* info
* action


#### How To Implement
This detection does not require you to ingest any new data. The detection does require the ability to search the _audit index. This detection may assist in efforts to find password spraying or brute force authorization attempts in addition to someone enumerating usernames.

#### Known False Positives
Automation executing authentication attempts against your Splunk infrastructure with outdated credentials may cause false positives.

#### Associated Analytic story
* [Splunk Vulnerabilities](/stories/splunk_vulnerabilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | $TotalFailedAuths$ failed authentication events to Splunk from $src$ detected. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.splunk.com/en_us/product-security/announcements/svd-2022-0502.html](https://www.splunk.com/en_us/product-security/announcements/svd-2022-0502.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/splunkd_auth/audittrail.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/splunkd_auth/audittrail.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/application/splunk_user_enumeration_attempt.yml) \| *version*: **1**