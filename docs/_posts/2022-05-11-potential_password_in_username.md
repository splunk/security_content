---
title: "Potential password in username"
excerpt: "Local Accounts
, Credentials In Files
"
categories:
  - Endpoint
last_modified_at: 2022-05-11
toc: true
toc_label: ""
tags:
  - Local Accounts
  - Credentials In Files
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search identifies users who have entered their passwords in username fields. This is done by looking for failed authentication attempts using usernames with a length longer than 7 characters and a high Shannon entropy, and looks for the next successful authentication attempt from the same source system to the same destination system as the failed attempt.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2022-05-11
- **Author**: Mikael Bjerkeland, Splunk
- **ID**: 5ced34b4-ab32-4bb0-8f22-3b8f186f0a38


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Local Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Credentials In Files | Credential Access |

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


</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` earliest(_time) AS starttime latest(_time) AS endtime latest(sourcetype) AS sourcetype values(Authentication.src) AS src values(Authentication.dest) AS dest count FROM datamodel=Authentication WHERE nodename=Authentication.Failed_Authentication BY "Authentication.user" 
| `drop_dm_object_name(Authentication)` 
| lookup ut_shannon_lookup word AS user 
| where ut_shannon>3 AND len(user)>=8 AND mvcount(src) == 1 
| sort count, - ut_shannon 
| eval incorrect_cred=user 
| eval endtime=endtime+1000 
| map maxsearches=70 search="
| tstats `security_content_summariesonly` earliest(_time) AS starttime latest(_time) AS endtime latest(sourcetype) AS sourcetype values(Authentication.src) AS src values(Authentication.dest) AS dest count FROM datamodel=Authentication WHERE nodename=Authentication.Successful_Authentication Authentication.src=\"$src$\" Authentication.dest=\"$dest$\" sourcetype IN (\"$sourcetype$\") earliest=\"$starttime$\" latest=\"$endtime$\" BY \"Authentication.user\" 
| `drop_dm_object_name(\"Authentication\")` 
| `potential_password_in_username_false_positive_reduction` 
| eval incorrect_cred=\"$incorrect_cred$\" 
| eval ut_shannon=\"$ut_shannon$\" 
| sort count" 
| where user!=incorrect_cred 
| outlier action=RM count 
| `potential_password_in_username_filter`
```

#### Macros
The SPL above uses the following Macros:
* [potential_password_in_username_false_positive_reduction](https://github.com/splunk/security_content/blob/develop/macros/potential_password_in_username_false_positive_reduction.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **potential_password_in_username_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* Authentication.user
* Authentication.src
* Authentication.dest
* sourcetype


#### How To Implement
To successfully implement this search, you need to have relevant authentication logs mapped to the Authentication data model. You also need to have the Splunk TA URL Toolbox (https://splunkbase.splunk.com/app/2734/) installed. The detection must run with a time interval shorter than endtime+1000.

#### Known False Positives
Valid usernames with high entropy or source/destination system pairs with multiple authenticating users will make it difficult to identify the real user authenticating.

#### Associated Analytic story
* [Credential Dumping](/stories/credential_dumping)
* [Insider Threat](/stories/insider_threat)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 21.0 | 30 | 70 | Potential password in username ($user$) with Shannon entropy ($ut_shannon$) |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://medium.com/@markmotig/search-for-passwords-accidentally-typed-into-the-username-field-975f1a389928](https://medium.com/@markmotig/search-for-passwords-accidentally-typed-into-the-username-field-975f1a389928)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.001/password_in_username/linux_secure.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.001/password_in_username/linux_secure.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/potential_password_in_username.yml) \| *version*: **1**