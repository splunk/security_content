---
title: "O365 Excessive Authentication Failures Alert"
excerpt: "Brute Force"
categories:
  - Cloud
last_modified_at: 2020-12-16
toc: true
toc_label: ""
tags:
  - Brute Force
  - Credential Access
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects when an excessive number of authentication failures occur this search also includes attempts against MFA prompt codes

- **Type**: Anomaly
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-12-16
- **Author**: Rod Soto, Splunk
- **ID**: d441364c-349c-453b-b55f-12eccab67cf9


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |

#### Search

```
`o365_management_activity` Workload=AzureActiveDirectory UserAuthenticationMethod=* status=Failed 
| stats count earliest(_time) as firstTime latest(_time) values(UserAuthenticationMethod) AS UserAuthenticationMethod values(UserAgent) AS UserAgent values(status) AS status values(src_ip) AS src_ip by user 
| where count > 10 
|`security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `o365_excessive_authentication_failures_alert_filter`
```

#### Associated Analytic Story
* [Office 365 Detections](/stories/office_365_detections)


#### How To Implement
You must install splunk Microsoft Office 365 add-on. This search works with o365:management:activity

#### Required field
* _time
* Workload
* UserAuthenticationMethod
* status
* UserAgent
* src_ip
* user


#### Kill Chain Phase
* Not Applicable


#### Known False Positives
The threshold for alert is above 10 attempts and this should reduce the number of false positives.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | User $user$ has caused excessive number of authentication failures from $src_ip$ using UserAgent $UserAgent$. |




#### Reference

* [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110/o365_brute_force_login/o365_brute_force_login.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110/o365_brute_force_login/o365_brute_force_login.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/o365_excessive_authentication_failures_alert.yml) \| *version*: **1**