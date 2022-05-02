---
title: "AWS Cloud Provisioning From Previously Unseen Region"
excerpt: "Unused/Unsupported Cloud Regions
"
categories:
  - Deprecated
last_modified_at: 2018-03-16
toc: true
toc_label: ""
tags:
  - Unused/Unsupported Cloud Regions
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS provisioning activities from previously unseen regions. Region in this context is similar to a state in the United States. Provisioning activities are defined broadly as any event that begins with "Run" or "Create." This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2018-03-16
- **Author**: David Dorsey, Splunk
- **ID**: 7971d3df-da82-4648-a6e5-b5637bea5253


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1535](https://attack.mitre.org/techniques/T1535/) | Unused/Unsupported Cloud Regions | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


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
`cloudtrail` (eventName=Run* OR eventName=Create*) 
| iplocation sourceIPAddress 
| search Region=* [search `cloudtrail` (eventName=Run* OR eventName=Create*) 
| iplocation sourceIPAddress 
| search Region=* 
| stats earliest(_time) as firstTime, latest(_time) as lastTime by sourceIPAddress, City, Region, Country 
| inputlookup append=t previously_seen_provisioning_activity_src.csv 
| stats min(firstTime) as firstTime max(lastTime) as lastTime by sourceIPAddress, City, Region, Country 
| outputlookup previously_seen_provisioning_activity_src.csv 
| stats min(firstTime) as firstTime max(lastTime) as lastTime by Region 
| eval newRegion=if(firstTime >= relative_time(now(), "-70m@m"), 1, 0) 
| where newRegion=1 
| table Region] 
| spath output=user userIdentity.arn 
| rename sourceIPAddress as src_ip 
| table _time, user, src_ip, Region, eventName, errorCode 
| `aws_cloud_provisioning_from_previously_unseen_region_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that **aws_cloud_provisioning_from_previously_unseen_region_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* sourceIPAddress


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. This search works best when you run the "Previously Seen AWS Provisioning Activity Sources" support search once to create a history of previously seen locations that have provisioned AWS resources.

#### Known False Positives
This is a strictly behavioral search, so we define "false positive" slightly differently. Every time this fires, it will accurately reflect the first occurrence in the time period you're searching within, plus what is stored in the cache feature. But while there are really no "false positives" in a traditional sense, there is definitely lots of noise.\
 This search will fire any time a new region is seen in the **GeoIP** database for any kind of provisioning activity. If you typically do all provisioning from tools inside of your region, there should be few false positives. If you are located in regions where the free version of **MaxMind GeoIP** that ships by default with Splunk has weak resolution (particularly small countries in less economically powerful regions), this may be much less valuable to you.

#### Associated Analytic story
* [AWS Suspicious Provisioning Activities](/stories/aws_suspicious_provisioning_activities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/aws_cloud_provisioning_from_previously_unseen_region.yml) \| *version*: **1**