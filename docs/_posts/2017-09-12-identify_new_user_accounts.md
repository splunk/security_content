---
title: "Identify New User Accounts"
excerpt: "Domain Accounts
"
categories:
  - Deprecated
last_modified_at: 2017-09-12
toc: true
toc_label: ""
tags:
  - Domain Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This detection search will help profile user accounts in your environment by identifying newly created accounts that have been added to your network in the past week.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2017-09-12
- **Author**: Bhavin Patel, Splunk
- **ID**: 475b9e27-17e4-46e2-b7e2-648221be3b89


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

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

* PR.IP



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

| from datamodel Identity_Management.All_Identities  
| eval empStatus=case((now()-startDate)<604800, "Accounts created in last week") 
| search empStatus="Accounts created in last week"
| `security_content_ctime(endDate)` 
| `security_content_ctime(startDate)`
| table identity empStatus endDate startDate 
| `identify_new_user_accounts_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **identify_new_user_accounts_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this search, you need to be populating the Enterprise Security Identity_Management data model in the assets and identity framework.

#### Known False Positives
If the Identity_Management data model is not updated regularly, this search could give you false positive alerts. Please consider this and investigate appropriately.

#### Associated Analytic story
* [Account Monitoring and Controls](/stories/account_monitoring_and_controls)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/identify_new_user_accounts.yml) \| *version*: **1**