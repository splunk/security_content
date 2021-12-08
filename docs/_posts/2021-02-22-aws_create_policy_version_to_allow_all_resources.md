---
title: "AWS Create Policy Version to allow all resources"
excerpt: "Cloud Accounts, Valid Accounts"
categories:
  - Cloud
last_modified_at: 2021-02-22
toc: true
toc_label: ""
tags:
  - Cloud Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events where a user created a policy version that allows them to access any resource in their account

- **Type**: TTP
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-02-22
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6340-4345-b5ad-212bf3d0dac4


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`cloudtrail` eventName=CreatePolicyVersion eventSource = iam.amazonaws.com errorCode = success 
| spath input=requestParameters.policyDocument output=key_policy_statements path=Statement{} 
| mvexpand key_policy_statements 
| spath input=key_policy_statements output=key_policy_action_1 path=Action 
| search key_policy_action_1 = "*" 
| stats count min(_time) as firstTime max(_time) as lastTime values(key_policy_statements) as policy_added by eventName eventSource aws_account_id errorCode userAgent eventID awsRegion userIdentity.principalId user_arn 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
|`aws_create_policy_version_to_allow_all_resources_filter`
```

#### Associated Analytic Story
* [AWS IAM Privilege Escalation](/stories/aws_iam_privilege_escalation)


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Required field
* _time
* eventName
* userAgent
* errorCode
* requestParameters.userName


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
While this search has no known false positives, it is possible that an AWS admin has legitimately created a policy to allow a user to access all resources. That said, AWS strongly advises against granting full control to all AWS resources


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | User $user$ created a policy version that allows them to access any resource in their account |




#### Reference

* [https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)
* [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_create_policy_version/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_create_policy_version/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_create_policy_version_to_allow_all_resources.yml) \| *version*: **2**