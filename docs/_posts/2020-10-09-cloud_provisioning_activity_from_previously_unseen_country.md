---
title: "Cloud Provisioning Activity From Previously Unseen Country"
excerpt: "Valid Accounts
"
categories:
  - Cloud
last_modified_at: 2020-10-09
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

This search looks for cloud provisioning activities from previously unseen countries. Provisioning activities are defined broadly as any event that runs or creates something.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)- **Datasource**: [Splunk Add-on for Amazon Kinesis Firehose](https://splunkbase.splunk.com/app/3719)
- **Last Updated**: 2020-10-09
- **Author**: Rico Valdez, Bhavin Patel, Splunk
- **ID**: 94994255-3acf-4213-9b3f-0494df03bb31


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
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

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **cloud_provisioning_activity_from_previously_unseen_country_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_cloud_provisioning_activity_sources](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_cloud_provisioning_activity_sources.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_cloud_provisioning_activity_sources.csv)

#### Required field
* _time
* All_Changes.action
* All_Changes.status
* All_Changes.src
* All_Changes.user
* All_Changes.object
* All_Changes.command


#### How To Implement
You must be ingesting your cloud infrastructure logs from your cloud provider.  You should run the baseline search `Previously Seen Cloud Provisioning Activity Sources - Initial` to build the initial table of source IP address, geographic locations, and times. You must also enable the second baseline search `Previously Seen Cloud Provisioning Activity Sources - Update` to keep this table up to date and to age out old data. You can adjust the time window for this search by updating the `previously_unseen_cloud_provisioning_activity_window` macro. You can also provide additional filtering for this search by customizing the `cloud_provisioning_activity_from_previously_unseen_country_filter` macro.

#### Known False Positives
This is a strictly behavioral search, so we define "false positive" slightly differently. Every time this fires, it will accurately reflect the first occurrence in the time period you're searching within, plus what is stored in the cache feature. But while there are really no "false positives" in a traditional sense, there is definitely lots of noise.\
 This search will fire any time a new IP address is seen in the **GeoIP** database for any kind of provisioning activity. If you typically do all provisioning from tools inside of your country, there should be few false positives. If you are located in countries where the free version of **MaxMind GeoIP** that ships by default with Splunk has weak resolution (particularly small countries in less economically powerful regions), this may be much less valuable to you.

#### Associated Analytic story
* [Suspicious Cloud Provisioning Activities](/stories/suspicious_cloud_provisioning_activities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | User $user$ is starting or creating an instance $object$ for the first time in Country $Country$ from IP address $src$ |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/cloud_provisioning_activity_from_previously_unseen_country.yml) \| *version*: **1**