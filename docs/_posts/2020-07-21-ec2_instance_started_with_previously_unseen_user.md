---
title: "EC2 Instance Started With Previously Unseen User"
excerpt: "Cloud Accounts
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Cloud Accounts
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

This search looks for EC2 instances being created by users who have not created them before. This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk
- **ID**: 22773e84-bac0-4595-b086-20d3f735b4f1


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`cloudtrail` eventName=RunInstances [search `cloudtrail` eventName=RunInstances errorCode=success 
| stats earliest(_time) as firstTime latest(_time) as lastTime by userIdentity.arn 
| rename userIdentity.arn as arn 
| inputlookup append=t previously_seen_ec2_launches_by_user.csv 
| stats min(firstTime) as firstTime, max(lastTime) as lastTime by arn 
| outputlookup previously_seen_ec2_launches_by_user.csv 
| eval newUser=if(firstTime >= relative_time(now(), "-70m@m"), 1, 0) 
| where newUser=1 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| rename arn as userIdentity.arn 
| table userIdentity.arn] 
| rename requestParameters.instanceType as instanceType, responseElements.instancesSet.items{}.instanceId as dest, userIdentity.arn as user 
| table _time, user, dest, instanceType 
| `ec2_instance_started_with_previously_unseen_user_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `ec2_instance_started_with_previously_unseen_user_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* errorCode
* userIdentity.arn


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. This search works best when you run the "Previously Seen EC2 Launches By User" support search once to create a history of previously seen ARNs.

#### Known False Positives
It's possible that a user will start to create EC2 instances when they haven't before for any number of reasons. Verify with the user that is launching instances that this is the intended behavior.

#### Associated Analytic story
* [AWS Cryptomining](/stories/aws_cryptomining)
* [Suspicious AWS EC2 Activities](/stories/suspicious_aws_ec2_activities)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/ec2_instance_started_with_previously_unseen_user.yml) \| *version*: **2**