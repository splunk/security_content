---
title: "aws detect permanent key creation"
excerpt: "Valid Accounts
"
categories:
  - Cloud
last_modified_at: 2020-07-27
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
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of accounts creating permanent keys. Permanent keys are not created by default and they are only needed for programmatic calls. Creation of Permanent key is an important event to monitor.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-07-27
- **Author**: Rod Soto, Splunk
- **ID**: 12d6d713-3cb4-4ffc-a064-1dca3d1cca01


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`aws_cloudwatchlogs_eks` CreateAccessKey 
| spath eventName 
| search eventName=CreateAccessKey "userIdentity.type"=IAMUser 
| table sourceIPAddress userName userIdentity.type userAgent action status responseElements.accessKey.createDate responseElements.accessKey.status responseElements.accessKey.accessKeyId 
|`aws_detect_permanent_key_creation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [aws_cloudwatchlogs_eks](https://github.com/splunk/security_content/blob/develop/macros/aws_cloudwatchlogs_eks.yml)

Note that `aws_detect_permanent_key_creation_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* userIdentity.type
* sourceIPAddress
* userName userIdentity.type
* userAgent
* action
* status
* responseElements.accessKey.createDate
* esponseElements.accessKey.status
* responseElements.accessKey.accessKeyId


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with cloudwatch logs

#### Known False Positives
Not all permanent key creations are malicious. If there is a policy of rotating keys this search can be adjusted to provide better context.

#### Associated Analytic story
* [AWS Cross Account Activity](/stories/aws_cross_account_activity)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/aws_detect_permanent_key_creation.yml) \| *version*: **1**