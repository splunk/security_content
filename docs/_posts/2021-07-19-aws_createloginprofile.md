---
title: "AWS CreateLoginProfile"
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

This search looks for AWS CloudTrail events where a user A(victim A) creates a login profile for user B, followed by a AWS Console login event from user B from the same src_ip as user B. This correlated event can be indicative of privilege escalation since both events happened from the same src_ip

- **Type**: TTP
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-07-19
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6340-4345-11ad-212bf444d111


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | Cloud Account | Persistence |


#### Search

```
`cloudtrail` eventName = CreateLoginProfile 
| rename requestParameters.userName as new_login_profile 
| table src_ip eventName new_login_profile userIdentity.userName  
| join new_login_profile src_ip [
| search `cloudtrail` eventName = ConsoleLogin 
| rename userIdentity.userName  as new_login_profile 
| stats count values(eventName) min(_time) as firstTime max(_time) as lastTime by eventSource aws_account_id errorCode userAgent eventID awsRegion userIdentity.principalId user_arn new_login_profile src_ip 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`] 
| `aws_createloginprofile_filter`
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
While this search has no known false positives, it is possible that an AWS admin has legitimately created a login profile for another user.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | User $user_arn$ is attempting to create a login profile for $requestParameters.userName$ and did a console login from this IP $src_ip$ |



#### Reference

* [https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)
* [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_createloginprofile/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_createloginprofile/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_createloginprofile.yml) \| *version*: **2**