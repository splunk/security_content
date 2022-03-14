---
title: "AWS CreateAccessKey"
excerpt: "Cloud Account
, Create Account
"
categories:
  - Cloud
last_modified_at: 2021-07-19
toc: true
toc_label: ""
tags:
  - Cloud Account
  - Create Account
  - Persistence
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events where a user A who has already permission to create access keys, makes an API call to create access keys for another user B. Attackers have been know to use this technique for Privilege Escalation in case new victim(user B) has more permissions than old victim(user B)

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-07-19
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6340-4345-11ad-212bf3d0d111


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | Cloud Account | Persistence |

| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Persistence |

#### Search

```
`cloudtrail` eventName = CreateAccessKey userAgent !=console.amazonaws.com errorCode = success
| search userIdentity.userName!=requestParameters.userName  
|  stats count min(_time) as firstTime max(_time) as lastTime  by requestParameters.userName src eventName eventSource aws_account_id errorCode userAgent eventID awsRegion userIdentity.principalId user_arn 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
|`aws_createaccesskey_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `aws_createaccesskey_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* userAgent
* errorCode
* requestParameters.userName


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Known False Positives
While this search has no known false positives, it is possible that an AWS admin has legitimately created keys for another user.

#### Associated Analytic story
* [AWS IAM Privilege Escalation](/stories/aws_iam_privilege_escalation)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | User $user_arn$ is attempting to create access keys for $requestParameters.userName$ from this IP $src$ |




#### Reference

* [https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)
* [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_createaccesskey/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_createaccesskey/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_createaccesskey.yml) \| *version*: **2**