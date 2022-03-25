---
title: "Detect AWS Console Login by User from New Region"
excerpt: "Unused/Unsupported Cloud Regions
"
categories:
  - Cloud
last_modified_at: 2020-10-07
toc: true
toc_label: ""
tags:
  - Unused/Unsupported Cloud Regions
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events wherein a console login event by a user was recorded within the last hour, then compares the event to a lookup file of previously seen users (by ARN values) who have logged into the console. The alert is fired if the user has logged into the console for the first time within the last hour

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)

- **Last Updated**: 2020-10-07
- **Author**: Bhavin Patel, Splunk
- **ID**: 9f31aa8e-e37c-46bc-bce1-8b3be646d026


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1535](https://attack.mitre.org/techniques/T1535/) | Unused/Unsupported Cloud Regions | Defense Evasion |

#### Search

```

| tstats earliest(_time) as firstTime latest(_time) as lastTime from datamodel=Authentication where Authentication.signature=ConsoleLogin by Authentication.user Authentication.src 
| iplocation Authentication.src 
| `drop_dm_object_name(Authentication)` 
| table firstTime lastTime user Region 
| join user  type=outer [
| inputlookup previously_seen_users_console_logins 
| stats min(firstTime) AS earliestseen by user Region 
| fields earliestseen user Region] 
| eval userRegion=if(firstTime >= relative_time(now(), "-24h@h"), "New Region","Previously Seen Region") 
| eval userStatus=if(earliestseen >= relative_time(now(), "-24h@h") OR isnull(earliestseen), "New User","Old User") 
| where userRegion = "New Region" AND userStatus != "Old User" 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| table firstTime lastTime user Region  userStatus userRegion  
| `detect_aws_console_login_by_user_from_new_region_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `detect_aws_console_login_by_user_from_new_region_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_users_console_logins](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_users_console_logins.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_users_console_logins.csv)

#### Required field
* _time
* Authentication.signature
* Authentication.user
* Authentication.src


#### How To Implement
You must install and configure the Splunk Add-on for AWS (version 5.1.0 or later) and Enterprise Security 6.2, which contains the required updates to the Authentication data model for cloud use cases. Run the `Previously Seen Users in AWS CloudTrail - Initial` support search only once to create a baseline of previously seen IAM users within the last 30 days. Run `Previously Seen Users in AWS CloudTrail - Update` hourly (or more frequently depending on how often you run the detection searches) to refresh the baselines. You can also provide additional filtering for this search by customizing the `detect_aws_console_login_by_user_from_new_region_filter` macro.

#### Known False Positives
When a legitimate new user logins for the first time, this activity will be detected. Check how old the account is and verify that the user activity is legitimate.

#### Associated Analytic story
* [Suspicious AWS Login Activities](/stories/suspicious_aws_login_activities)
* [Suspicious Cloud Authentication Activities](/stories/suspicious_cloud_authentication_activities)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | User $user$ is logging into the AWS console from Region $Region$ for the first time |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/detect_aws_console_login_by_user_from_new_region.yml) \| *version*: **1**