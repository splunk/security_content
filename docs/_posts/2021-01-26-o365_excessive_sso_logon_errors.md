---
title: "O365 Excessive SSO logon errors"
excerpt: "Modify Authentication Process
"
categories:
  - Cloud
last_modified_at: 2021-01-26
toc: true
toc_label: ""
tags:
  - Modify Authentication Process
  - Credential Access
  - Defense Evasion
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects accounts with high number of Single Sign ON (SSO) logon errors. Excessive logon errors may indicate attempts to bruteforce of password or single sign on token hijack or reuse.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-01-26
- **Author**: Rod Soto, Splunk
- **ID**: 8158ccc4-6038-11eb-ae93-0242ac130002


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1556](https://attack.mitre.org/techniques/T1556/) | Modify Authentication Process | Credential Access, Defense Evasion, Persistence |

#### Search

```
`o365_management_activity`  Workload=AzureActiveDirectory LogonError=SsoArtifactInvalidOrExpired 
| stats count min(_time) as firstTime max(_time) as lastTime by LogonError ActorIpAddress UserAgent UserId 
| where count > 5 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `o365_excessive_sso_logon_errors_filter`
```

#### Macros
The SPL above uses the following Macros:
* [o365_management_activity](https://github.com/splunk/security_content/blob/develop/macros/o365_management_activity.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `o365_excessive_sso_logon_errors_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Workload
* LogonError
* ActorIpAddress
* UserAgent
* UserId


#### How To Implement
You must install splunk Microsoft Office 365 add-on. This search works with o365:management:activity

#### Known False Positives
Logon errors may not be malicious in nature however it may indicate attempts to reuse a token or password obtained via credential access attack.

#### Associated Analytic story
* [Office 365 Detections](/stories/office_365_detections)
* [Cloud Federated Credential Abuse](/stories/cloud_federated_credential_abuse)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | User $UserId$ has caused excessive number of SSO logon errors from $ActorIpAddress$ using UserAgent $UserAgent$. |




#### Reference

* [https://stealthbits.com/blog/bypassing-mfa-with-pass-the-cookie/](https://stealthbits.com/blog/bypassing-mfa-with-pass-the-cookie/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/o365_sso_logon_errors/o365_sso_logon_errors.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/o365_sso_logon_errors/o365_sso_logon_errors.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/o365_excessive_sso_logon_errors.yml) \| *version*: **1**