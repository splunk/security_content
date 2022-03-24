---
title: "Cloud Compute Instance Created With Previously Unseen Instance Type"
excerpt: ""
categories:
  - Cloud
last_modified_at: 2020-09-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Find EC2 instances being created with previously unseen instance types.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Datasource**: [Splunk Add-on for Amazon Kinesis Firehose](https://splunkbase.splunk.com/app/3719)
- **Last Updated**: 2020-09-12
- **Author**: David Dorsey, Splunk
- **ID**: c6ddbf53-9715-49f3-bb4c-fb2e8a309cda

#### Search

```

| tstats earliest(_time) as firstTime, latest(_time) as lastTime values(All_Changes.object_id) as dest, count from datamodel=Change where All_Changes.action=created by All_Changes.Instance_Changes.instance_type, All_Changes.user 
| `drop_dm_object_name("All_Changes")` 
| `drop_dm_object_name("Instance_Changes")` 
| where instance_type != "unknown" 
| lookup previously_seen_cloud_compute_instance_types instance_type as instance_type OUTPUTNEW firstTimeSeen, enough_data 
| eventstats max(enough_data) as enough_data 
| where enough_data=1 
| eval firstTimeSeenInstanceType=min(firstTimeSeen) 
| where isnull(firstTimeSeenInstanceType) OR firstTimeSeenInstanceType > relative_time(now(), "-24h@h") 
| table firstTime, user, dest, count, instance_type 
| `security_content_ctime(firstTime)` 
| `cloud_compute_instance_created_with_previously_unseen_instance_type_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `cloud_compute_instance_created_with_previously_unseen_instance_type_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_cloud_compute_instance_types](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_cloud_compute_instance_types.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_cloud_compute_instance_types.csv)

#### Required field
* _time
* All_Changes.object_id
* All_Changes.action
* All_Changes.Instance_Changes.instance_type
* All_Changes.user


#### How To Implement
You must be ingesting your cloud infrastructure logs from your cloud provider. You should run the baseline search `Previously Seen Cloud Compute Instance Types - Initial` to build the initial table of instance types observed and times. You must also enable the second baseline search `Previously Seen Cloud Compute Instance Types - Update` to keep this table up to date and to age out old data. You can also provide additional filtering for this search by customizing the `cloud_compute_instance_created_with_previously_unseen_instance_type_filter` macro.

#### Known False Positives
It is possible that an admin will create a new system using a new instance type that has never been used before. Verify with the creator that they intended to create the system with the new instance type.

#### Associated Analytic story
* [Cloud Cryptomining](/stories/cloud_cryptomining)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 50 | 60 | User $user$ is creating an instance $dest$ with an instance type $instance_type$ that has not been previously seen. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_compute_instance_created_with_previously_unseen_instance_type.yml) \| *version*: **1**