---
title: "aws detect sts assume role abuse"
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

This search provides detection of suspicious use of sts:AssumeRole. These tokens can be created on the go and used by attackers to move laterally and escalate privileges.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-27
- **Author**: Rod Soto, Splunk
- **ID**: 8e565314-b6a2-46d8-9f05-1a34a176a662


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`cloudtrail` user_type=AssumedRole userIdentity.sessionContext.sessionIssuer.type=Role 
| table sourceIPAddress userIdentity.arn user_agent user_access_key status action requestParameters.roleName responseElements.role.roleName responseElements.role.createDate 
| `aws_detect_sts_assume_role_abuse_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `aws_detect_sts_assume_role_abuse_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* user_type
* userIdentity.sessionContext.sessionIssuer.type
* sourceIPAddress
* userIdentity.arn
* user_agent
* user_access_key
* status
* action
* requestParameters.roleName
* esponseElements.role.roleName
* esponseElements.role.createDate


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs

#### Known False Positives
Sts:AssumeRole can be very noisy as it is a standard mechanism to provide cross account and cross resources access. This search can be adjusted to provide specific values to identify cases of abuse.

#### Associated Analytic story
* [AWS Cross Account Activity](/stories/aws_cross_account_activity)


#### Kill Chain Phase
* Lateral Movement






#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/aws_detect_sts_assume_role_abuse.yml) \| *version*: **1**