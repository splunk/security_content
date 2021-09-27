---
title: "Cloud Provisioning Activity From Previously Unseen Country"
excerpt: "Valid Accounts"
categories:
  - Cloud
last_modified_at: 2020-10-09
toc: true
tags:
  - Anomaly
  - T1078
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

This search looks for cloud provisioning activities from previously unseen countries. Provisioning activities are defined broadly as any event that runs or creates something.

- **Type**: Anomaly
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-10-09
- **Author**: Rico Valdez, Bhavin Patel, Splunk
- **ID**: 94994255-3acf-4213-9b3f-0494df03bb31


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |



#### Search

```

| tstats earliest(_time) as firstTime, latest(_time) as lastTime from datamodel=Change where (All_Changes.action=started OR All_Changes.action=created) All_Changes.status=success by All_Changes.src, All_Changes.user, All_Changes.object, All_Changes.command 
| `drop_dm_object_name("All_Changes")` 
| iplocation src 
| where isnotnull(Country) 
| lookup previously_seen_cloud_provisioning_activity_sources Country as Country OUTPUT firstTimeSeen, enough_data 
| eventstats max(enough_data) as enough_data 
| where enough_data=1 
| eval firstTimeSeenCountry=min(firstTimeSeen) 
| where isnull(firstTimeSeenCountry) OR firstTimeSeenCountry > relative_time(now(), "-24h@h") 
| table firstTime, src, Country, user, object, command 
| `cloud_provisioning_activity_from_previously_unseen_country_filter` 
| `security_content_ctime(firstTime)`
```

#### Associated Analytic Story
* [Suspicious Cloud Provisioning Activities](/stories/suspicious_cloud_provisioning_activities)


#### How To Implement
You must be ingesting your cloud infrastructure logs from your cloud provider.  You should run the baseline search `Previously Seen Cloud Provisioning Activity Sources - Initial` to build the initial table of source IP address, geographic locations, and times. You must also enable the second baseline search `Previously Seen Cloud Provisioning Activity Sources - Update` to keep this table up to date and to age out old data. You can adjust the time window for this search by updating the `previously_unseen_cloud_provisioning_activity_window` macro. You can also provide additional filtering for this search by customizing the `cloud_provisioning_activity_from_previously_unseen_country_filter` macro.

#### Required field
* _time
* All_Changes.action
* All_Changes.status
* All_Changes.src
* All_Changes.user
* All_Changes.object
* All_Changes.command


#### Kill Chain Phase


#### Known False Positives
This is a strictly behavioral search, so we define &#34;false positive&#34; slightly differently. Every time this fires, it will accurately reflect the first occurrence in the time period you&#39;re searching within, plus what is stored in the cache feature. But while there are really no &#34;false positives&#34; in a traditional sense, there is definitely lots of noise.\
 This search will fire any time a new IP address is seen in the **GeoIP** database for any kind of provisioning activity. If you typically do all provisioning from tools inside of your country, there should be few false positives. If you are located in countries where the free version of **MaxMind GeoIP** that ships by default with Splunk has weak resolution (particularly small countries in less economically powerful regions), this may be much less valuable to you.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | User $user$ is starting or creating an instance $object$ for the first time in Country $Country$ from IP address $src$ |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_provisioning_activity_from_previously_unseen_country.yml) \| *version*: **1**