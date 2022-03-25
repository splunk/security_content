---
title: "AWS SetDefaultPolicyVersion"
excerpt: "Cloud Accounts
, Valid Accounts
"
categories:
  - Cloud
last_modified_at: 2021-03-02
toc: true
toc_label: ""
tags:
  - Cloud Accounts
  - Valid Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events where a user has set a default policy versions. Attackers have been know to use this technique for Privilege Escalation in case the previous versions of the policy had permissions to access more resources than the current version of the policy

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-03-02
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6340-4345-11ad-212bf3d0dac4


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`cloudtrail` eventName=SetDefaultPolicyVersion eventSource = iam.amazonaws.com 
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.policyArn) as policy_arn by src requestParameters.versionId eventName eventSource aws_account_id errorCode userAgent eventID awsRegion userIdentity.principalId user_arn 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_setdefaultpolicyversion_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `aws_setdefaultpolicyversion_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* userAgent
* errorCode
* requestParameters.userName
* eventSource


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Known False Positives
While this search has no known false positives, it is possible that an AWS admin has legitimately set a default policy to allow a user to access all resources. That said, AWS strongly advises against granting full control to all AWS resources

#### Associated Analytic story
* [AWS IAM Privilege Escalation](/stories/aws_iam_privilege_escalation)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 50 | 60 | From IP address $sourceIPAddress$, user agent $userAgent$ has trigged an event $eventName$ for updating the the default policy version |




#### Reference

* [https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)
* [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_setdefaultpolicyversion/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_setdefaultpolicyversion/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_setdefaultpolicyversion.yml) \| *version*: **1**