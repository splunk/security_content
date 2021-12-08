---
title: "Cloud Instance Modified By Previously Unseen User"
excerpt: "Cloud Accounts, Valid Accounts"
categories:
  - Cloud
last_modified_at: 2020-07-29
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

This search looks for cloud instances being modified by users who have not previously modified them.

- **Type**: Anomaly
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-07-29
- **Author**: Rico Valdez, Splunk
- **ID**: 7fb15084-b14e-405a-bd61-a6de15a40722


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count earliest(_time) as firstTime, latest(_time) as lastTime values(All_Changes.object_id) as object_id values(All_Changes.command) as command from datamodel=Change where All_Changes.action=modified All_Changes.change_type=EC2 All_Changes.status=success by All_Changes.user 
| `drop_dm_object_name("All_Changes")` 
| lookup previously_seen_cloud_instance_modifications_by_user user as user OUTPUTNEW firstTimeSeen, enough_data 
| eventstats max(enough_data) as enough_data 
| where enough_data=1 
| eval firstTimeSeenUser=min(firstTimeSeen) 
| where isnull(firstTimeSeenUser) OR firstTimeSeenUser > relative_time(now(), "-24h@h") 
| table firstTime user command object_id count 
| `security_content_ctime(firstTime)` 
| `cloud_instance_modified_by_previously_unseen_user_filter`
```

#### Associated Analytic Story
* [Suspicious Cloud Instance Activities](/stories/suspicious_cloud_instance_activities)


#### How To Implement
This search has a dependency on other searches to create and update a baseline of users observed to be associated with this activity. The search &#34;Previously Seen Cloud Instance Modifications By User - Update&#34; should be enabled for this detection to properly work.

#### Required field
* _time
* All_Changes.object_id
* All_Changes.command
* All_Changes.action
* All_Changes.change_type
* All_Changes.status
* All_Changes.user


#### Kill Chain Phase


#### Known False Positives
It&#39;s possible that a new user will start to modify EC2 instances when they haven&#39;t before for any number of reasons. Verify with the user that is modifying instances that this is the intended behavior.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | User $user$ is modifying an instance $dest$ for the first time. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_instance_modified_by_previously_unseen_user.yml) \| *version*: **1**