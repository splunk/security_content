---
title: "EC2 Instance Started In Previously Unseen Region"
excerpt: "Unused/Unsupported Cloud Regions
"
categories:
  - Deprecated
last_modified_at: 2018-02-23
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

This search looks for AWS CloudTrail events where an instance is started in a particular region in the last one hour and then compares it to a lookup file of previously seen regions where an instance was started

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2018-02-23
- **Author**: Bhavin Patel, Splunk
- **ID**: ada0f478-84a8-4641-a3f3-d82362d6fd75


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

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.DP
* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 12



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudtrail` earliest=-1h StartInstances 
| stats earliest(_time) as earliest latest(_time) as latest by awsRegion 
| inputlookup append=t previously_seen_aws_regions.csv 
| stats min(earliest) as earliest max(latest) as latest by awsRegion 
| outputlookup previously_seen_aws_regions.csv 
| eval regionStatus=if(earliest >= relative_time(now(),"-1d@d"), "Instance Started in a New Region","Previously Seen Region") 
| `security_content_ctime(earliest)` 
| `security_content_ctime(latest)` 
| where regionStatus="Instance Started in a New Region" 
| `ec2_instance_started_in_previously_unseen_region_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **ec2_instance_started_in_previously_unseen_region_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* awsRegion


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. Run the "Previously seen AWS Regions" support search only once to create of baseline of previously seen regions.  This search is deprecated and have been translated to use the latest Change Datamodel.

#### Known False Positives
It's possible that a user has unknowingly started an instance in a new region. Please verify that this activity is legitimate.

#### Associated Analytic story
* [AWS Cryptomining](/stories/aws_cryptomining)
* [Suspicious AWS EC2 Activities](/stories/suspicious_aws_ec2_activities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/ec2_instance_started_in_previously_unseen_region.yml) \| *version*: **1**