---
title: "Cloud Instance Modified By Previously Unseen User"
excerpt: "Cloud Accounts
, Valid Accounts
"
categories:
  - Cloud
last_modified_at: 2020-07-29
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

This search looks for cloud instances being modified by users who have not previously modified them.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)- **Datasource**: [Splunk Add-on for Amazon Kinesis Firehose](https://splunkbase.splunk.com/app/3719)
- **Last Updated**: 2020-07-29
- **Author**: Rico Valdez, Splunk
- **ID**: 7fb15084-b14e-405a-bd61-a6de15a40722


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* ID.AM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 1



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

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

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **cloud_instance_modified_by_previously_unseen_user_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_cloud_instance_modifications_by_user](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_cloud_instance_modifications_by_user.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_cloud_instance_modifications_by_user.csv)

#### Required field
* _time
* All_Changes.object_id
* All_Changes.command
* All_Changes.action
* All_Changes.change_type
* All_Changes.status
* All_Changes.user


#### How To Implement
This search has a dependency on other searches to create and update a baseline of users observed to be associated with this activity. The search "Previously Seen Cloud Instance Modifications By User - Update" should be enabled for this detection to properly work.

#### Known False Positives
It's possible that a new user will start to modify EC2 instances when they haven't before for any number of reasons. Verify with the user that is modifying instances that this is the intended behavior.

#### Associated Analytic story
* [Suspicious Cloud Instance Activities](/stories/suspicious_cloud_instance_activities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | User $user$ is modifying an instance $dest$ for the first time. |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_instance_modified_by_previously_unseen_user.yml) \| *version*: **1**