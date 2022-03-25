---
title: "EC2 Instance Modified With Previously Unseen User"
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

This search looks for EC2 instances being modified by users who have not previously modified them. This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk
- **ID**: 56f91724-cf3f-4666-84e1-e3712fb41e76


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`cloudtrail` `ec2_modification_api_calls` [search `cloudtrail` `ec2_modification_api_calls` errorCode=success 
| stats earliest(_time) as firstTime latest(_time) as lastTime by userIdentity.arn 
| rename userIdentity.arn as arn 
| inputlookup append=t previously_seen_ec2_modifications_by_user 
| stats min(firstTime) as firstTime, max(lastTime) as lastTime by arn 
| outputlookup previously_seen_ec2_modifications_by_user 
| eval newUser=if(firstTime >= relative_time(now(), "-70m@m"), 1, 0) 
| where newUser=1 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| rename arn as userIdentity.arn 
| table userIdentity.arn] 
| spath output=dest responseElements.instancesSet.items{}.instanceId 
| spath output=user userIdentity.arn 
| table _time, user, dest 
| `ec2_instance_modified_with_previously_unseen_user_filter`
```

#### Macros
The SPL above uses the following Macros:
* [ec2_modification_api_calls](https://github.com/splunk/security_content/blob/develop/macros/ec2_modification_api_calls.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `ec2_instance_modified_with_previously_unseen_user_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_ec2_modifications_by_user](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_ec2_modifications_by_user.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_ec2_modifications_by_user.csv)
* [previously_seen_ec2_modifications_by_user](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_ec2_modifications_by_user.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_ec2_modifications_by_user.csv)

#### Required field
* _time
* errorCode
* userIdentity.arn


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. This search works best when you run the "Previously Seen EC2 Launches By User" support search once to create a history of previously seen ARNs. To add or remove APIs that modify an EC2 instance, edit the macro `ec2_modification_api_calls`.

#### Known False Positives
It's possible that a new user will start to modify EC2 instances when they haven't before for any number of reasons. Verify with the user that is modifying instances that this is the intended behavior.

#### Associated Analytic story
* [Unusual AWS EC2 Modifications](/stories/unusual_aws_ec2_modifications)


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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/ec2_instance_modified_with_previously_unseen_user.yml) \| *version*: **3**