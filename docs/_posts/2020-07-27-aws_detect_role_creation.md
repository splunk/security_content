---
title: "aws detect role creation"
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
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of role creation by IAM users. Role creation is an event by itself if user is creating a new role with trust policies different than the available in AWS and it can be used for lateral movement and escalation of privileges.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-27
- **Author**: Rod Soto, Splunk
- **ID**: 5f04081e-ddee-4353-afe4-504f288de9ad


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`aws_cloudwatchlogs_eks` event_name=CreateRole action=created userIdentity.type=AssumedRole requestParameters.description=Allows* 
| table sourceIPAddress userIdentity.principalId userIdentity.arn action event_name awsRegion http_user_agent mfa_auth msg requestParameters.roleName requestParameters.description responseElements.role.arn responseElements.role.createDate 
| `aws_detect_role_creation_filter`
```

#### Associated Analytic Story
* [AWS Cross Account Activity](/stories/aws_cross_account_activity)


#### How To Implement
You must install splunk AWS add-on and Splunk App for AWS. This search works with cloudwatch logs

#### Required field
* _time
* event_name
* action
* userIdentity.type
* requestParameters.description
* sourceIPAddress
* userIdentity.principalId
* userIdentity.arn
* action
* event_name
* awsRegion
* http_user_agent
* mfa_auth
* msg
* requestParameters.roleName
* requestParameters.description
* responseElements.role.arn
* responseElements.role.createDate


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
CreateRole is not very common in common users. This search can be adjusted to provide specific values to identify cases of abuse. In general AWS provides plenty of trust policies that fit most use cases.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/aws_detect_role_creation.yml) \| *version*: **1**