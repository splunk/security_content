---
title: "Abnormally High Number Of Cloud Instances Launched"
excerpt: "Cloud Accounts
, Valid Accounts
"
categories:
  - Cloud
last_modified_at: 2020-08-21
toc: true
toc_label: ""
tags:
  - Cloud Accounts
  - Valid Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search finds for the number successfully created cloud instances for every 4 hour block. This is split up between weekdays and the weekend. It then applies the probability densitiy model previously created and alerts on any outliers.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)

- **Last Updated**: 2020-08-21
- **Author**: David Dorsey, Splunk
- **ID**: f2361e9f-3928-496c-a556-120cd4223a65


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```

| tstats count as instances_launched values(All_Changes.object_id) as object_id from datamodel=Change where (All_Changes.action=created) AND All_Changes.status=success AND All_Changes.object_category=instance by All_Changes.user _time span=1h 
| `drop_dm_object_name("All_Changes")` 
| eval HourOfDay=strftime(_time, "%H") 
| eval HourOfDay=floor(HourOfDay/4)*4 
| eval DayOfWeek=strftime(_time, "%w") 
| eval isWeekend=if(DayOfWeek >= 1 AND DayOfWeek <= 5, 0, 1) 
| join HourOfDay isWeekend [summary cloud_excessive_instances_created_v1] 
| where cardinality >=16 
| apply cloud_excessive_instances_created_v1 threshold=0.005 
| rename "IsOutlier(instances_launched)" as isOutlier 
| where isOutlier=1 
| eval expected_upper_threshold = mvindex(split(mvindex(BoundaryRanges, -1), ":"), 0) 
| eval distance_from_threshold = instances_launched - expected_upper_threshold 
| table _time, user, instances_launched, expected_upper_threshold, distance_from_threshold, object_id 
| `abnormally_high_number_of_cloud_instances_launched_filter`
```

#### Macros
The SPL above uses the following Macros:

Note that `abnormally_high_number_of_cloud_instances_launched_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Changes.object_id
* All_Changes.action
* All_Changes.status
* All_Changes.object_category
* All_Changes.user


#### How To Implement
You must be ingesting your cloud infrastructure logs. You also must run the baseline search `Baseline Of Cloud Instances Launched` to create the probability density function.

#### Known False Positives
Many service accounts configured within an AWS infrastructure are known to exhibit this behavior. Please adjust the threshold values and filter out service accounts from the output. Always verify if this search alerted on a human user.

#### Associated Analytic story
* [Cloud Cryptomining](/stories/cloud_cryptomining)
* [Suspicious Cloud Instance Activities](/stories/suspicious_cloud_instance_activities)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/abnormally_high_number_of_cloud_instances_launched.yml) \| *version*: **2**