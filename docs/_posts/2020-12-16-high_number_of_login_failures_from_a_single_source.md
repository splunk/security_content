---
title: "High Number of Login Failures from a single source"
excerpt: "Password Guessing
, Brute Force
"
categories:
  - Cloud
last_modified_at: 2020-12-16
toc: true
toc_label: ""
tags:
  - Password Guessing
  - Brute Force
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search will detect more than 5 login failures in Office365 Azure Active Directory from a single source IP address. Please adjust the threshold value of 5 as suited for your environment.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-12-16
- **Author**: Bhavin Patel, Splunk
- **ID**: 7f398cfb-918d-41f4-8db8-2e2474e02222


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Credential Access |

| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |

#### Search

```
`o365_management_activity` Operation=UserLoginFailed  record_type=AzureActiveDirectoryStsLogon app=AzureActiveDirectory 
| stats count dc(user) as accounts_locked values(user) as user values(LogonError) as LogonError values(authentication_method) as authentication_method values(signature) as signature values(UserAgent) as UserAgent by src_ip record_type Operation app 
| search accounts_locked >= 5
| `high_number_of_login_failures_from_a_single_source_filter`
```

#### Macros
The SPL above uses the following Macros:
* [o365_management_activity](https://github.com/splunk/security_content/blob/develop/macros/o365_management_activity.yml)

Note that `high_number_of_login_failures_from_a_single_source_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Operation
* record_type
* app
* user
* LogonError
* authentication_method
* signature
* UserAgent
* src_ip
* record_type


#### How To Implement


#### Known False Positives
unknown

#### Associated Analytic story
* [Office 365 Detections](/stories/office_365_detections)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/high_number_of_login_failures_from_a_single_source.yml) \| *version*: **1**