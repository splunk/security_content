---
title: "Cloud Compute Instance Created In Previously Unused Region"
excerpt: "Unused/Unsupported Cloud Regions"
categories:
  - Cloud
last_modified_at: 2020-09-02
toc: true
toc_label: ""
tags:
  - Unused/Unsupported Cloud Regions
  - Defense Evasion
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks at cloud-infrastructure events where an instance is created in any region within the last hour and then compares it to a lookup file of previously seen regions where instances have been created.

- **Type**: Anomaly
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-09-02
- **Author**: David Dorsey, Splunk
- **ID**: fa4089e2-50e3-40f7-8469-d2cc1564ca59


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1535](https://attack.mitre.org/techniques/T1535/) | Unused/Unsupported Cloud Regions | Defense Evasion |

#### Search

```

| tstats earliest(_time) as firstTime latest(_time) as lastTime values(All_Changes.object_id) as dest, count from datamodel=Change where All_Changes.action=created by All_Changes.vendor_region, All_Changes.user 
| `drop_dm_object_name("All_Changes")` 
| lookup previously_seen_cloud_regions vendor_region as vendor_region OUTPUTNEW firstTimeSeen, enough_data 
| eventstats max(enough_data) as enough_data 
| where enough_data=1 
| eval firstTimeSeenRegion=min(firstTimeSeen) 
| where isnull(firstTimeSeenRegion) OR firstTimeSeenRegion > relative_time(now(), "-24h@h") 
| table firstTime, user, dest, count , vendor_region 
| `security_content_ctime(firstTime)` 
| `cloud_compute_instance_created_in_previously_unused_region_filter`
```

#### Associated Analytic Story
* [Cloud Cryptomining](/stories/cloud_cryptomining)


#### How To Implement
You must be ingesting your cloud infrastructure logs from your cloud provider. You should run the baseline search `Previously Seen Cloud Regions - Initial` to build the initial table of images observed and times. You must also enable the second baseline search `Previously Seen Cloud Regions - Update` to keep this table up to date and to age out old data. You can also provide additional filtering for this search by customizing the `cloud_compute_instance_created_in_previously_unused_region_filter` macro.

#### Required field
* _time
* All_Changes.object_id
* All_Changes.action
* All_Changes.vendor_region
* All_Changes.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
It&#39;s possible that a user has unknowingly started an instance in a new region. Please verify that this activity is legitimate.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | User $user$ is creating an instance $dest$ in a new region for the first time |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_compute_instance_created_in_previously_unused_region.yml) \| *version*: **1**