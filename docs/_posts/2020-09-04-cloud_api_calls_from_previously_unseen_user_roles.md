---
title: "Cloud API Calls From Previously Unseen User Roles"
excerpt: "Valid Accounts
"
categories:
  - Cloud
last_modified_at: 2020-09-04
toc: true
toc_label: ""
tags:
  - Valid Accounts
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

This search looks for new commands from each user role.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Datasource**: [Splunk Add-on for Amazon Kinesis Firehose](https://splunkbase.splunk.com/app/3719)
- **Last Updated**: 2020-09-04
- **Author**: David Dorsey, Splunk
- **ID**: 2181ad1f-1e73-4d0c-9780-e8880482a08f


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```

| tstats earliest(_time) as firstTime, latest(_time) as lastTime from datamodel=Change where All_Changes.user_type=AssumedRole AND All_Changes.status=success by All_Changes.user, All_Changes.command All_Changes.object 
| `drop_dm_object_name("All_Changes")` 
| lookup previously_seen_cloud_api_calls_per_user_role user as user, command as command OUTPUT firstTimeSeen, enough_data 
| eventstats max(enough_data) as enough_data 
| where enough_data=1 
| eval firstTimeSeenUserApiCall=min(firstTimeSeen) 
| where isnull(firstTimeSeenUserApiCall) OR firstTimeSeenUserApiCall > relative_time(now(),"-24h@h") 
| table firstTime, user, object, command 
|`security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `cloud_api_calls_from_previously_unseen_user_roles_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `cloud_api_calls_from_previously_unseen_user_roles_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_cloud_api_calls_per_user_role](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_cloud_api_calls_per_user_role.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_cloud_api_calls_per_user_role.csv)

#### Required field
* _time
* All_Changes.user
* All_Changes.user_type
* All_Changes.status
* All_Changes.command
* All_Changes.object


#### How To Implement
You must be ingesting your cloud infrastructure logs from your cloud provider.  You should run the baseline search `Previously Seen Cloud API Calls Per User Role - Initial` to build the initial table of user roles, commands, and times. You must also enable the second baseline search `Previously Seen Cloud API Calls Per User Role - Update` to keep this table up to date and to age out old data. You can adjust the time window for this search by updating the `cloud_api_calls_from_previously_unseen_user_roles_activity_window` macro. You can also provide additional filtering for this search by customizing the `cloud_api_calls_from_previously_unseen_user_roles_filter`

#### Known False Positives
.

#### Associated Analytic story
* [Suspicious Cloud User Activities](/stories/suspicious_cloud_user_activities)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | User $user$ of type AssumedRole attempting to execute new API calls $command$ that have not been seen before |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_api_calls_from_previously_unseen_user_roles.yml) \| *version*: **1**