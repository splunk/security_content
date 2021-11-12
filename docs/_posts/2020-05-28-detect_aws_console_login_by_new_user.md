---
title: "Detect AWS Console Login by New User"
excerpt: ""
categories:
  - Cloud
last_modified_at: 2020-05-28
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events wherein a console login event by a user was recorded within the last hour, then compares the event to a lookup file of previously seen users (by ARN values) who have logged into the console. The alert is fired if the user has logged into the console for the first time within the last hour

- **Type**: Hunting
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2020-05-28
- **Author**: Rico Valdez, Splunk
- **ID**: bc91a8cd-35e7-4bb2-6140-e756cc46fd71

#### Search

```

| tstats earliest(_time) as firstTime latest(_time) as lastTime from datamodel=Authentication where Authentication.signature=ConsoleLogin by Authentication.user 
| `drop_dm_object_name(Authentication)` 
| inputlookup append=t previously_seen_users_console_logins 
| stats min(firstTime) as firstTime max(lastTime) as lastTime by user 
| eval userStatus=if(firstTime >=relative_time(now(),"-24h@h"), "First Time Logging into AWS Console", "Previously Seen User") 
|where userStatus="First Time Logging into AWS Console" 
|  `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `detect_aws_console_login_by_new_user_filter`
```

#### Associated Analytic Story
* [Suspicious Cloud Authentication Activities](/stories/suspicious_cloud_authentication_activities)


#### How To Implement
You must install and configure the Splunk Add-on for AWS (version 5.1.0 or later) and Enterprise Security 6.2, which contains the required updates to the Authentication data model for cloud use cases. Run the `Previously Seen Users in AWS CloudTrail - Initial` support search only once to create a baseline of previously seen IAM users within the last 30 days. Run `Previously Seen Users in AWS CloudTrail - Update` hourly (or more frequently depending on how often you run the detection searches) to refresh the baselines.

#### Required field
* _time
* Authentication.signature
* Authentication.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
When a legitimate new user logins for the first time, this activity will be detected. Check how old the account is and verify that the user activity is legitimate.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 50 | 60 | User $user$ is logging into the AWS console for the first time |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/detect_aws_console_login_by_new_user.yml) \| *version*: **1**