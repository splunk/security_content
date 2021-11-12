---
title: "Abnormally High Number Of Cloud Instances Destroyed"
excerpt: "Cloud Accounts, Valid Accounts"
categories:
  - Cloud
last_modified_at: 2020-08-21
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

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search finds for the number successfully destroyed cloud instances for every 4 hour block. This is split up between weekdays and the weekend. It then applies the probability densitiy model previously created and alerts on any outliers.

- **Type**: Anomaly
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-08-21
- **Author**: David Dorsey, Splunk
- **ID**: ef629fc9-1583-4590-b62a-f2247fbf7bbf


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```

| tstats count as instances_destroyed values(All_Changes.object_id) as object_id from datamodel=Change where All_Changes.action=deleted AND All_Changes.status=success AND All_Changes.object_category=instance by All_Changes.user _time span=1h 
| `drop_dm_object_name("All_Changes")` 
| eval HourOfDay=strftime(_time, "%H") 
| eval HourOfDay=floor(HourOfDay/4)*4 
| eval DayOfWeek=strftime(_time, "%w") 
| eval isWeekend=if(DayOfWeek >= 1 AND DayOfWeek <= 5, 0, 1) 
| join HourOfDay isWeekend [summary cloud_excessive_instances_destroyed_v1] 
| where cardinality >=16 
| apply cloud_excessive_instances_destroyed_v1 threshold=0.005 
| rename "IsOutlier(instances_destroyed)" as isOutlier 
| where isOutlier=1 
| eval expected_upper_threshold = mvindex(split(mvindex(BoundaryRanges, -1), ":"), 0) 
| eval distance_from_threshold = instances_destroyed - expected_upper_threshold 
| table _time, user, instances_destroyed, expected_upper_threshold, distance_from_threshold, object_id 
| `abnormally_high_number_of_cloud_instances_destroyed_filter`
```

#### Associated Analytic Story
* [Suspicious Cloud Instance Activities](/stories/suspicious_cloud_instance_activities)


#### How To Implement
You must be ingesting your cloud infrastructure logs. You also must run the baseline search `Baseline Of Cloud Instances Destroyed` to create the probability density function.

#### Required field
* _time
* All_Changes.object_id
* All_Changes.action
* All_Changes.status
* All_Changes.object_category
* All_Changes.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Many service accounts configured within a cloud infrastructure are known to exhibit this behavior. Please adjust the threshold values and filter out service accounts from the output. Always verify if this search alerted on a human user.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/abnormally_high_number_of_cloud_instances_destroyed.yml) \| *version*: **1**