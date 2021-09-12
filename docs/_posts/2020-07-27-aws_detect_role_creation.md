---
title: "AWS Detect Role Creation"
last_modified_at: 2020-07-27
categories:
  - Cloud
tags:
  - T1078
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

This search provides detection of role creation by IAM users. Role creation is an event by itself if user is creating a new role with trust policies different than the available in AWS and it can be used for late
ral movement and escalation of privileges.

#### Search
```
`aws_cloudwatchlogs_eks` event_name=CreateRole action=created userIdentity.type=AssumedRole requestParameters.description=Allows*
| table sourceIPAddress userIdentity.principalId userIdentity.arn action event_name awsRegion http_user_agent mfa_auth msg requestParameters.roleName requestParameters.description responseElements.role.arn respon
seElements.role.createDate
| `aws_detect_role_creation_filter`
```
#### Associated Analytic Story

* AWS Cross Account Activity


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


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |


#### Kill Chain Phase

* Lateral Movement


#### Known False Positives
CreateRole is not very common in common users. This search can be adjusted to provide specific values to identify cases of abuse. In general AWS provides plenty of trust policies that fit most use cases.

#### Reference


#### Test Dataset


_version_: 1
