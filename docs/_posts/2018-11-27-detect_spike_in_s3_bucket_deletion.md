---
title: "Detect Spike in S3 Bucket deletion"
excerpt: "Data from Cloud Storage Object"
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

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects users creating spikes in API activity related to deletion of S3 buckets in your AWS environment. It will also update the cache file that factors in the latest data.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-11-27
- **Author**: Bhavin Patel, Splunk
- **ID**: ad12w478-84a8-4641-a3w1-e32372q4bd53


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage Object | Collection |

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

#### Associated Analytic Story
* [Suspicious AWS S3 Activities](/stories/suspicious_aws_s3_activities)


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. You can modify `dataPointThreshold` and `deviationThreshold` to better fit your environment. The `dataPointThreshold` variable is the minimum number of data points required to have a statistically significant amount of data to determine. The `deviationThreshold` variable is the number of standard deviations away from the mean that the value must be to be considered a spike. This search works best when you run the &#34;Baseline of S3 Bucket deletion activity by ARN&#34; support search once to create a baseline of previously seen S3 bucket-deletion activity.

#### Required field
* _time
* eventName
* userIdentity.arn


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Based on the values of`dataPointThreshold` and `deviationThreshold`, the false positive rate may vary. Please modify this according the your environment.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/detect_spike_in_s3_bucket_deletion.yml) \| *version*: **1**