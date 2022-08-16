---
title: "AWS Defense Evasion PutBucketLifecycle"
excerpt: "Disable Cloud Logs
, Impair Defenses
"
categories:
  - Cloud
last_modified_at: 2022-07-25
toc: true
toc_label: ""
tags:
  - Disable Cloud Logs
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies `PutBucketLifecycle` events in CloudTrail logs where a user has created a new lifecycle rule for an S3 bucket with a short expiration period. Attackers may use this API call to impair the CloudTrail logging by removing logs from the S3 bucket by changing the object expiration day to 1 day, in which case the CloudTrail logs will be deleted.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-07-25
- **Author**: Bhavin Patel
- **ID**: ce1c0e2b-9303-4903-818b-0d9002fc6ea4


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | Disable Cloud Logs | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```
`cloudtrail` eventName=PutBucketLifecycle user_type=IAMUser errorCode=success 
|  spath path=requestParameters{}.LifecycleConfiguration{}.Rule{}.Expiration{}.Days output=expiration_days 
|  spath path=requestParameters{}.bucketName output=bucket_name 
| stats count min(_time) as firstTime max(_time) as lastTime  by src region eventName userAgent user_arn aws_account_id expiration_days  bucket_name user_type
| `security_content_ctime(firstTime)` 
|  `security_content_ctime(lastTime)` 
| where expiration_days < 3 
| `aws_defense_evasion_putbucketlifecycle_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **aws_defense_evasion_putbucketlifecycle_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* eventSource
* requestParameters.name
* userAgent
* aws_account_id
* src
* region
* requestParameters{}.LifecycleConfiguration{}.Rule{}.Expiration{}.Days
* requestParameters{}.bucketName


#### How To Implement
You must install Splunk AWS Add on and enable CloudTrail logs in your AWS Environment. We recommend our users to set the expiration days value according to your company's log retention policies.

#### Known False Positives
While this search has no known false positives, it is possible that it is a legitimate admin activity. Please consider filtering out these noisy events using userAgent, user_arn field names.

#### Associated Analytic story
* [AWS Defense Evasion](/stories/aws_defense_evasion)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 20.0 | 50 | 40 | User $user_arn$ has created a new rule to on an S3 bucket $bucket_name$ with short expiration days |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-lifecycle-rule/](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-lifecycle-rule/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/put_bucketlifecycle/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/put_bucketlifecycle/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_defense_evasion_putbucketlifecycle.yml) \| *version*: **1**