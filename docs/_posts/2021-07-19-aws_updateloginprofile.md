---
title: "AWS UpdateLoginProfile"
excerpt: "Cloud Account"
categories:
  - Cloud
last_modified_at: 2021-07-19
toc: true
tags:
  - TTP
  - T1136.003
  - Cloud Account
  - Persistence
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events where a user A who has already permission to update login profile, makes an API call to update login profile for another user B . Attackers have been know to use this technique for Privilege Escalation in case new victim(user B) has more permissions than old victim(user B)

- **Type**: TTP
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-07-19
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6a40-4115-11ad-212bf3d0d111


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | Cloud Account | Persistence |


#### Search

```
`cloudtrail` eventName = UpdateLoginProfile userAgent !=console.amazonaws.com errorCode = success
| search userIdentity.userName!=requestParameters.userName  
|  stats count min(_time) as firstTime max(_time) as lastTime  by requestParameters.userName src eventName eventSource aws_account_id errorCode userAgent eventID awsRegion userIdentity.userName user_arn 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
|`aws_updateloginprofile_filter`
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
While this search has no known false positives, it is possible that an AWS admin has legitimately created keys for another user.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 50 | 60 | From IP address $sourceIPAddress$, user agent $userAgent$ has trigged an event $eventName$ for updating the existing login profile, potentially giving user $user_arn$ more access privilleges |



#### Reference

* [https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)
* [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_updateloginprofile/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_updateloginprofile/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_updateloginprofile.yml) \| *version*: **2**