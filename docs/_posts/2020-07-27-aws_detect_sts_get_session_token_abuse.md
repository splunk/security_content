---
title: "AWS Detect STS Get Session Token Abuse"
last_modified_at: 2020-07-27
categories:
  - Endpoint
tags:
  - T1550
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

This search provides detection of suspicious use of sts:GetSessionToken. These tokens can be created on the go and used by attackers to move laterally and escalate privileges.

#### Search
```
`aws_cloudwatchlogs_eks` ASIA  userIdentity.type=IAMUser
| spath eventName
| search eventName=GetSessionToken
| table sourceIPAddress eventTime userIdentity.arn userName userAgent user_type status region
| `aws_detect_sts_get_session_token_abuse_filter`
```
#### Associated Analytic Story

* AWS Cross Account Activity


#### How To Implement
You must install splunk AWS add-on and Splunk App for AWS. This search works with cloudwatch logs

#### Required field

* _time
* userIdentity.type
* eventName
* sourceIPAddress
* eventTime
* userIdentity.arn
* userName
* userAgent
* user_type
* status
* region

#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1550 | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |


#### Kill Chain Phase

* Lateral Movement

#### Known False Positives
Sts:GetSessionToken can be very noisy as in certain environments numerous calls of this type can be executed. This search can be adjusted to provide specific values to identify cases of abuse. In specific environments the use of field requestParameters.serialNumber will need to be used.

#### Reference


#### Test Dataset
