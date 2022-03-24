---
title: "Cloud Compute Instance Created With Previously Unseen Image"
excerpt: ""
categories:
  - Cloud
last_modified_at: 2018-10-12
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

This search looks for cloud compute instances being created with previously unseen image IDs.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Datasource**: [Splunk Add-on for Amazon Kinesis Firehose](https://splunkbase.splunk.com/app/3719)
- **Last Updated**: 2018-10-12
- **Author**: David Dorsey, Splunk
- **ID**: bc24922d-987c-4645-b288-f8c73ec194c4

#### Search

```

| tstats count earliest(_time) as firstTime, latest(_time) as lastTime values(All_Changes.object_id) as dest from datamodel=Change where All_Changes.action=created by All_Changes.Instance_Changes.image_id, All_Changes.user 
| `drop_dm_object_name("All_Changes")` 
| `drop_dm_object_name("Instance_Changes")` 
| where image_id != "unknown" 
| lookup previously_seen_cloud_compute_images image_id as image_id OUTPUT firstTimeSeen, enough_data 
| eventstats max(enough_data) as enough_data 
| where enough_data=1 
| eval firstTimeSeenImage=min(firstTimeSeen) 
| where isnull(firstTimeSeenImage) OR firstTimeSeenImage > relative_time(now(), "-24h@h") 
| table firstTime, user, image_id, count, dest 
| `security_content_ctime(firstTime)` 
| `cloud_compute_instance_created_with_previously_unseen_image_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `cloud_compute_instance_created_with_previously_unseen_image_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_cloud_compute_images](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_cloud_compute_images.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_cloud_compute_images.csv)

#### Required field
* _time
* All_Changes.object_id
* All_Changes.action
* All_Changes.Instance_Changes.image_id
* All_Changes.user


#### How To Implement
You must be ingesting your cloud infrastructure logs from your cloud provider. You should run the baseline search `Previously Seen Cloud Compute Images - Initial` to build the initial table of images observed and times. You must also enable the second baseline search `Previously Seen Cloud Compute Images - Update` to keep this table up to date and to age out old data. You can also provide additional filtering for this search by customizing the `cloud_compute_instance_created_with_previously_unseen_image_filter` macro.

#### Known False Positives
After a new image is created, the first systems created with that image will cause this alert to fire.  Verify that the image being used was created by a legitimate user.

#### Associated Analytic story
* [Cloud Cryptomining](/stories/cloud_cryptomining)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | User $user$ is creating an instance $dest$ with an image that has not been previously seen. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_compute_instance_created_with_previously_unseen_image.yml) \| *version*: **1**