---
title: "Cloud Provisioning Activity From Previously Unseen IP Address"
excerpt: "Valid Accounts
"
categories:
  - Cloud
last_modified_at: 2020-08-16
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

This search looks for cloud provisioning activities from previously unseen IP addresses. Provisioning activities are defined broadly as any event that runs or creates something.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Datasource**: [Splunk Add-on for Amazon Kinesis Firehose](https://splunkbase.splunk.com/app/3719)
- **Last Updated**: 2020-08-16
- **Author**: Rico Valdez, Splunk
- **ID**: f86a8ec9-b042-45eb-92f4-e9ed1d781078


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```

| tstats earliest(_time) as firstTime, latest(_time) as lastTime, values(All_Changes.object_id) as object_id from datamodel=Change where (All_Changes.action=started OR All_Changes.action=created) All_Changes.status=success by All_Changes.src, All_Changes.user, All_Changes.command 
| `drop_dm_object_name("All_Changes")` 
| lookup previously_seen_cloud_provisioning_activity_sources src as src OUTPUT firstTimeSeen, enough_data 
| eventstats max(enough_data) as enough_data 
| where enough_data=1 
| eval firstTimeSeenSrc=min(firstTimeSeen) 
| where isnull(firstTimeSeenSrc) OR firstTimeSeenSrc > relative_time(now(), `previously_unseen_cloud_provisioning_activity_window`) 
| table firstTime, src, user, object_id, command 
| `cloud_provisioning_activity_from_previously_unseen_ip_address_filter` 
| `security_content_ctime(firstTime)`
```

#### Macros
The SPL above uses the following Macros:
* [previously_unseen_cloud_provisioning_activity_window](https://github.com/splunk/security_content/blob/develop/macros/previously_unseen_cloud_provisioning_activity_window.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `cloud_provisioning_activity_from_previously_unseen_ip_address_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_cloud_provisioning_activity_sources](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_cloud_provisioning_activity_sources.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_cloud_provisioning_activity_sources.csv)

#### Required field
* _time
* All_Changes.object_id
* All_Changes.action
* All_Changes.status
* All_Changes.src
* All_Changes.user
* All_Changes.command


#### How To Implement
You must be ingesting your cloud infrastructure logs from your cloud provider.  You should run the baseline search `Previously Seen Cloud Provisioning Activity Sources - Initial` to build the initial table of source IP address, geographic locations, and times. You must also enable the second baseline search `Previously Seen Cloud Provisioning Activity Sources - Update` to keep this table up to date and to age out old data. You can adjust the time window for this search by updating the `previously_unseen_cloud_provisioning_activity_window` macro. You can also provide additional filtering for this search by customizing the `cloud_provisioning_activity_from_previously_unseen_ip_address_filter` macro.

#### Known False Positives
This is a strictly behavioral search, so we define "false positive" slightly differently. Every time this fires, it will accurately reflect the first occurrence in the time period you're searching within, plus what is stored in the cache feature. But while there are really no "false positives" in a traditional sense, there is definitely lots of noise.\
 This search will fire any time a new IP address is seen in the **GeoIP** database for any kind of provisioning activity. If you typically do all provisioning from tools inside of your country, there should be few false positives. If you are located in countries where the free version of **MaxMind GeoIP** that ships by default with Splunk has weak resolution (particularly small countries in less economically powerful regions), this may be much less valuable to you.

#### Associated Analytic story
* [Suspicious Cloud Provisioning Activities](/stories/suspicious_cloud_provisioning_activities)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | User $user$ is starting or creating an instance $object_id$ for the first time from IP address $src$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_provisioning_activity_from_previously_unseen_ip_address.yml) \| *version*: **1**