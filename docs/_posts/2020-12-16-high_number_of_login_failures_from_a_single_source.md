---
title: "High Number of Login Failures from a single source"
excerpt: "Password Guessing"
categories:
  - Cloud
last_modified_at: 2020-12-16
toc: true
tags:
  - Anomaly
  - T1110.001
  - Password Guessing
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---

#### Description

This search will detect more than 5 login failures in Office365 Azure Active Directory from a single source IP address. Please adjust the threshold value of 5 as suited for your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **Last Updated**: 2020-12-16
- **Author**: Bhavin Patel, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Credential Access |


#### Search

```
`o365_management_activity` Operation=UserLoginFailed  record_type=AzureActiveDirectoryStsLogon app=AzureActiveDirectory 
| stats count dc(user) as accounts_locked values(user) as user values(LogonError) as LogonError values(authentication_method) as authentication_method values(signature) as signature values(UserAgent) as UserAgent by src_ip record_type Operation app 
| search accounts_locked >= 5
| `high_number_of_login_failures_from_a_single_source_filter`
```

#### Associated Analytic Story
* [Office 365 Detections](_stories/office_365_detections)


#### How To Implement


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


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
unknown




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1