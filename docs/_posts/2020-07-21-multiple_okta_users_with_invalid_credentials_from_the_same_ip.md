---
title: "Multiple Okta Users With Invalid Credentials From The Same IP"
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

This search detects Okta login failures due to bad credentials for multiple users originating from the same ip address.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk
- **ID**: 19cba45f-cad3-4032-8911-0c09e0444552


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
`okta` outcome.reason=INVALID_CREDENTIALS 
| rename client.geographicalContext.country as country, client.geographicalContext.state as state, client.geographicalContext.city as city 
| stats min(_time) as firstTime max(_time) as lastTime dc(user) as distinct_users values(user) as users by src_ip, displayMessage, outcome.reason, country, state, city  
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
|  search distinct_users > 5
| `multiple_okta_users_with_invalid_credentials_from_the_same_ip_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [okta](https://github.com/splunk/security_content/blob/develop/macros/okta.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **multiple_okta_users_with_invalid_credentials_from_the_same_ip_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* outcome.reason
* client.geographicalContext.country
* client.geographicalContext.state
* client.geographicalContext.city
* user
* src_ip
* displayMessage


#### How To Implement
This search is specific to Okta and requires Okta logs are being ingested in your Splunk deployment.

#### Known False Positives
A single public IP address servicing multiple legitmate users may trigger this search. In addition, the threshold of 5 distinct users may be too low for your needs. You may modify the included filter macro `multiple_okta_users_with_invalid_credentials_from_the_same_ip_filter` to raise the threshold or except specific IP adresses from triggering this search.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/multiple_okta_users_with_invalid_credentials_from_the_same_ip.yml) \| *version*: **2**