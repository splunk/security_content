---
title: "Okta Failed SSO Attempts"
excerpt: "Valid Accounts
, Default Accounts
"
categories:
  - Application
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Default Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Detect failed Okta SSO events

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk
- **ID**: 371a6545-2618-4032-ad84-93386b8698c5


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

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
`okta` displayMessage="User attempted unauthorized access to app" 
| stats  min(_time) as firstTime max(_time) as lastTime values(app) as Apps count by user, result ,displayMessage, src_ip 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `okta_failed_sso_attempts_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [okta](https://github.com/splunk/security_content/blob/develop/macros/okta.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **okta_failed_sso_attempts_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* displayMessage
* app
* user
* result
* src_ip


#### How To Implement
This search is specific to Okta and requires Okta logs are being ingested in your Splunk deployment.

#### Known False Positives
There may be a faulty config preventing legitmate users from accessing apps they should have access to.

#### Associated Analytic story
* [Suspicious Okta Activity](/stories/suspicious_okta_activity)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/okta_failed_sso_attempts.yml) \| *version*: **2**