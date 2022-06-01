---
title: "Abnormally High AWS Instances Launched by User"
excerpt: "Cloud Accounts
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Cloud Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events where a user successfully launches an abnormally high number of instances. This search is deprecated and have been translated to use the latest Change Datamodel

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6340-4345-b5ad-290bf5d0dac4


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

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

* CIS 13



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```
`cloudtrail` eventName=RunInstances errorCode=success 
| bucket span=10m _time 
| stats count AS instances_launched by _time userName 
| eventstats avg(instances_launched) as total_launched_avg, stdev(instances_launched) as total_launched_stdev 
| eval threshold_value = 4 
| eval isOutlier=if(instances_launched > total_launched_avg+(total_launched_stdev * threshold_value), 1, 0) 
| search isOutlier=1 AND _time >= relative_time(now(), "-10m@m") 
| eval num_standard_deviations_away = round(abs(instances_launched - total_launched_avg) / total_launched_stdev, 2) 
| table _time, userName, instances_launched, num_standard_deviations_away, total_launched_avg, total_launched_stdev 
| `abnormally_high_aws_instances_launched_by_user_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

> :information_source:
> **abnormally_high_aws_instances_launched_by_user_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* errorCode
* userName


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. The threshold value should be tuned to your environment.

#### Known False Positives
Many service accounts configured within an AWS infrastructure are known to exhibit this behavior. Please adjust the threshold values and filter out service accounts from the output. Always verify if this search alerted on a human user.

#### Associated Analytic story
* [AWS Cryptomining](/stories/aws_cryptomining)
* [Suspicious AWS EC2 Activities](/stories/suspicious_aws_ec2_activities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/abnormally_high_aws_instances_launched_by_user.yml) \| *version*: **2**