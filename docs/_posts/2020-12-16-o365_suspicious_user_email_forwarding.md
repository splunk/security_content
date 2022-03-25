---
title: "O365 Suspicious User Email Forwarding"
excerpt: "Email Forwarding Rule
, Email Collection
"
categories:
  - Cloud
last_modified_at: 2020-12-16
toc: true
toc_label: ""
tags:
  - Email Forwarding Rule
  - Email Collection
  - Collection
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects when multiple user configured a forwarding rule to the same destination.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-12-16
- **Author**: Patrick Bareiss, Splunk
- **ID**: f8dfe015-dbb3-4569-ba75-b13787e06aa4


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | Email Forwarding Rule | Collection |

| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Collection |

#### Search

```
`o365_management_activity` Operation=Set-Mailbox 
| spath input=Parameters 
| rename Identity AS src_user 
| search ForwardingSmtpAddress=* 
| stats dc(src_user) AS count_src_user earliest(_time) as firstTime latest(_time) as lastTime values(src_user) AS src_user values(user) AS user by ForwardingSmtpAddress 
| where count_src_user > 1 
|`security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
|`o365_suspicious_user_email_forwarding_filter`
```

#### Macros
The SPL above uses the following Macros:
* [o365_management_activity](https://github.com/splunk/security_content/blob/develop/macros/o365_management_activity.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `o365_suspicious_user_email_forwarding_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Operation
* Parameters


#### How To Implement
You must install splunk Microsoft Office 365 add-on. This search works with o365:management:activity

#### Known False Positives
unknown

#### Associated Analytic story
* [Office 365 Detections](/stories/office_365_detections)
* [Data Exfiltration](/stories/data_exfiltration)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 80 | 60 | User $user$ configured multiple users $src_user$ with a count of $count_src_user$, a forwarding rule to same destination $ForwardingSmtpAddress$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.003/o365_email_forwarding_rule/o365_email_forwarding_rule.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.003/o365_email_forwarding_rule/o365_email_forwarding_rule.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/o365_suspicious_user_email_forwarding.yml) \| *version*: **1**