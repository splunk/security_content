---
title: "Abnormally High Number Of Cloud Security Group API Calls"
excerpt: "Cloud Accounts, Valid Accounts"
categories:
  - Cloud
last_modified_at: 2020-09-07
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
  - Change
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search will detect a spike in the number of API calls made to your cloud infrastructure environment about security groups by a user.

- **Type**: Anomaly
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-09-07
- **Author**: David Dorsey, Splunk
- **ID**: d4dfb7f3-7a37-498a-b5df-f19334e871af


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```

| tstats count as security_group_api_calls values(All_Changes.command) as command from datamodel=Change where All_Changes.object_category=firewall AND All_Changes.status=success by All_Changes.user _time span=1h 
| `drop_dm_object_name("All_Changes")` 
| eval HourOfDay=strftime(_time, "%H") 
| eval HourOfDay=floor(HourOfDay/4)*4 
| eval DayOfWeek=strftime(_time, "%w") 
| eval isWeekend=if(DayOfWeek >= 1 AND DayOfWeek <= 5, 0, 1) 
| join user HourOfDay isWeekend [ summary cloud_excessive_security_group_api_calls_v1] 
| where cardinality >=16 
| apply cloud_excessive_security_group_api_calls_v1 threshold=0.005 
| rename "IsOutlier(security_group_api_calls)" as isOutlier 
| where isOutlier=1 
| eval expected_upper_threshold = mvindex(split(mvindex(BoundaryRanges, -1), ":"), 0) 
| where security_group_api_calls > expected_upper_threshold 
| eval distance_from_threshold = security_group_api_calls - expected_upper_threshold 
| table _time, user, command, security_group_api_calls, expected_upper_threshold, distance_from_threshold 
| `abnormally_high_number_of_cloud_security_group_api_calls_filter`
```

#### Associated Analytic Story
* [Suspicious Cloud User Activities](/stories/suspicious_cloud_user_activities)


#### How To Implement
You must be ingesting your cloud infrastructure logs. You also must run the baseline search `Baseline Of Cloud Security Group API Calls Per User` to create the probability density function model.

#### Required field
* _time
* All_Changes.command
* All_Changes.object_category
* All_Changes.status
* All_Changes.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | user $user$ has made $api_calls$ api calls related to security groups, violating the dynamic threshold of $expected_upper_threshold$ with the following command $command$. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/abnormally_high_number_of_cloud_security_group_api_calls.yml) \| *version*: **1**