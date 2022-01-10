---
title: "aws detect permanent key creation"
excerpt: "Valid Accounts"
categories:
  - Cloud
last_modified_at: 2020-07-27
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of accounts creating permanent keys. Permanent keys are not created by default and they are only needed for programmatic calls. Creation of Permanent key is an important event to monitor.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-27
- **Author**: Rod Soto, Splunk
- **ID**: 12d6d713-3cb4-4ffc-a064-1dca3d1cca01


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`aws_cloudwatchlogs_eks` CreateAccessKey 
| spath eventName 
| search eventName=CreateAccessKey "userIdentity.type"=IAMUser 
| table sourceIPAddress userName userIdentity.type userAgent action status responseElements.accessKey.createDate responseElements.accessKey.status responseElements.accessKey.accessKeyId 
|`aws_detect_permanent_key_creation_filter`
```

#### Associated Analytic Story
* [AWS Cross Account Activity](/stories/aws_cross_account_activity)


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with cloudwatch logs

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


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
Not all permanent key creations are malicious. If there is a policy of rotating keys this search can be adjusted to provide better context.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/aws_detect_permanent_key_creation.yml) \| *version*: **1**