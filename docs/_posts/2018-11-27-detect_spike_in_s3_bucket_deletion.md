---
title: "Detect Spike in S3 Bucket deletion"
excerpt: "Data from Cloud Storage Object
"
categories:
  - Cloud
last_modified_at: 2018-11-27
toc: true
toc_label: ""
tags:
  - Data from Cloud Storage Object
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### :warning: WARNING THIS IS A EXPERIMENTAL analytic
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search detects users creating spikes in API activity related to deletion of S3 buckets in your AWS environment. It will also update the cache file that factors in the latest data.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2018-11-27
- **Author**: Bhavin Patel, Splunk
- **ID**: e733a326-59d2-446d-b8db-14a17151aa68


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage Object | Collection |

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
* DE.CM
* PR.AC



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
`cloudtrail` eventName=DeleteBucket [search `cloudtrail` eventName=DeleteBucket 
| spath output=arn path=userIdentity.arn 
| stats count as apiCalls by arn 
| inputlookup s3_deletion_baseline append=t 
| fields - latestCount 
| stats values(*) as * by arn 
| rename apiCalls as latestCount 
| eval newAvgApiCalls=avgApiCalls + (latestCount-avgApiCalls)/720 
| eval newStdevApiCalls=sqrt(((pow(stdevApiCalls, 2)*719 + (latestCount-newAvgApiCalls)*(latestCount-avgApiCalls))/720)) 
| eval avgApiCalls=coalesce(newAvgApiCalls, avgApiCalls), stdevApiCalls=coalesce(newStdevApiCalls, stdevApiCalls), numDataPoints=if(isnull(latestCount), numDataPoints, numDataPoints+1) 
| table arn, latestCount, numDataPoints, avgApiCalls, stdevApiCalls 
| outputlookup s3_deletion_baseline 
| eval dataPointThreshold = 15, deviationThreshold = 3 
| eval isSpike=if((latestCount > avgApiCalls+deviationThreshold*stdevApiCalls) AND numDataPoints > dataPointThreshold, 1, 0) 
| where isSpike=1 
| rename arn as userIdentity.arn 
| table userIdentity.arn] 
| spath output=user userIdentity.arn 
| spath output=bucketName path=requestParameters.bucketName 
| stats values(bucketName) as bucketName, count as numberOfApiCalls, dc(eventName) as uniqueApisCalled by user 
| `detect_spike_in_s3_bucket_deletion_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

> :information_source:
> **detect_spike_in_s3_bucket_deletion_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [s3_deletion_baseline](https://github.com/splunk/security_content/blob/develop/lookups/s3_deletion_baseline.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/s3_deletion_baseline.csv)
* [s3_deletion_baseline](https://github.com/splunk/security_content/blob/develop/lookups/s3_deletion_baseline.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/s3_deletion_baseline.csv)

#### Required field
* _time
* eventName
* userIdentity.arn


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. You can modify `dataPointThreshold` and `deviationThreshold` to better fit your environment. The `dataPointThreshold` variable is the minimum number of data points required to have a statistically significant amount of data to determine. The `deviationThreshold` variable is the number of standard deviations away from the mean that the value must be to be considered a spike. This search works best when you run the "Baseline of S3 Bucket deletion activity by ARN" support search once to create a baseline of previously seen S3 bucket-deletion activity.

#### Known False Positives
Based on the values of`dataPointThreshold` and `deviationThreshold`, the false positive rate may vary. Please modify this according the your environment.

#### Associated Analytic story
* [Suspicious AWS S3 Activities](/stories/suspicious_aws_s3_activities)




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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/detect_spike_in_s3_bucket_deletion.yml) \| *version*: **1**