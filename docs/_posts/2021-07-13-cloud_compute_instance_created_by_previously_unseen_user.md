---
title: "Cloud Compute Instance Created By Previously Unseen User"
excerpt: "Cloud Accounts
, Valid Accounts
"
categories:
  - Cloud
last_modified_at: 2021-07-13
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for cloud compute instances created by users who have not created them before.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Datasource**: [Splunk Add-on for Amazon Kinesis Firehose](https://splunkbase.splunk.com/app/3719)
- **Last Updated**: 2021-07-13
- **Author**: Rico Valdez, Splunk
- **ID**: 37a0ec8d-827e-4d6d-8025-cedf31f3a149


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count earliest(_time) as firstTime, latest(_time) as lastTime values(All_Changes.object) as dest from datamodel=Change where All_Changes.action=created by All_Changes.user All_Changes.vendor_region 
| `drop_dm_object_name("All_Changes")` 
| lookup previously_seen_cloud_compute_creations_by_user user as user OUTPUTNEW firstTimeSeen, enough_data 
| eventstats max(enough_data) as enough_data 
| where enough_data=1 
| eval firstTimeSeenUser=min(firstTimeSeen) 
| where isnull(firstTimeSeenUser) OR firstTimeSeenUser > relative_time(now(), "-24h@h") 
| table firstTime, user, dest, count vendor_region 
| `security_content_ctime(firstTime)` 
| `cloud_compute_instance_created_by_previously_unseen_user_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `cloud_compute_instance_created_by_previously_unseen_user_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_cloud_compute_creations_by_user](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_cloud_compute_creations_by_user.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_cloud_compute_creations_by_user.csv)

#### Required field
* _time
* All_Changes.object
* All_Changes.action
* All_Changes.user
* All_Changes.vendor_region


#### How To Implement
You must be ingesting the appropriate cloud-infrastructure logs Run the "Previously Seen Cloud Compute Creations By User" support search to create of baseline of previously seen users.

#### Known False Positives
It's possible that a user will start to create compute instances for the first time, for any number of reasons. Verify with the user launching instances that this is the intended behavior.

#### Associated Analytic story
* [Cloud Cryptomining](/stories/cloud_cryptomining)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 18.0 | 30 | 60 | User $user$ is creating a new instance $dest$ for the first time |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_compute_instance_created_by_previously_unseen_user.yml) \| *version*: **2**