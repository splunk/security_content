---
title: "Detect Spike in Security Group Activity"
excerpt: "Cloud Accounts
"
categories:
  - Deprecated
last_modified_at: 2018-04-18
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search will detect users creating spikes in API activity related to security groups in your AWS environment.  It will also update the cache file that factors in the latest data.  This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2018-04-18
- **Author**: Bhavin Patel, Splunk
- **ID**: ada0f478-84a8-4641-a3f1-e32372d4bd53


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`cloudtrail` `security_group_api_calls` [search `cloudtrail` `security_group_api_calls` 
| spath output=arn path=userIdentity.arn 
| stats count as apiCalls by arn 
| inputlookup security_group_activity_baseline append=t 
| fields - latestCount 
| stats values(*) as * by arn 
| rename apiCalls as latestCount 
| eval newAvgApiCalls=avgApiCalls + (latestCount-avgApiCalls)/720 
| eval newStdevApiCalls=sqrt(((pow(stdevApiCalls, 2)*719 + (latestCount-newAvgApiCalls)*(latestCount-avgApiCalls))/720)) 
| eval avgApiCalls=coalesce(newAvgApiCalls, avgApiCalls), stdevApiCalls=coalesce(newStdevApiCalls, stdevApiCalls), numDataPoints=if(isnull(latestCount), numDataPoints, numDataPoints+1) 
| table arn, latestCount, numDataPoints, avgApiCalls, stdevApiCalls 
| outputlookup security_group_activity_baseline 
| eval dataPointThreshold = 15, deviationThreshold = 3 
| eval isSpike=if((latestCount > avgApiCalls+deviationThreshold*stdevApiCalls) AND numDataPoints > dataPointThreshold, 1, 0) 
| where isSpike=1 
| rename arn as userIdentity.arn 
| table userIdentity.arn] 
| spath output=user userIdentity.arn 
| stats values(eventName) as eventNames, count as numberOfApiCalls, dc(eventName) as uniqueApisCalled by user 
| `detect_spike_in_security_group_activity_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_group_api_calls](https://github.com/splunk/security_content/blob/develop/macros/security_group_api_calls.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `detect_spike_in_security_group_activity_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [security_group_activity_baseline](https://github.com/splunk/security_content/blob/develop/lookups/security_group_activity_baseline.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/security_group_activity_baseline.csv)
* [security_group_activity_baseline](https://github.com/splunk/security_content/blob/develop/lookups/security_group_activity_baseline.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/security_group_activity_baseline.csv)

#### Required field
* _time
* serIdentity.arn


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. You can modify `dataPointThreshold` and `deviationThreshold` to better fit your environment. The `dataPointThreshold` variable is the minimum number of data points required to have a statistically significant amount of data to determine. The `deviationThreshold` variable is the number of standard deviations away from the mean that the value must be to be considered a spike.This search works best when you run the "Baseline of Security Group Activity by ARN" support search once to create a history of previously seen Security Group Activity. To add or remove API event names for security groups, edit the macro `security_group_api_calls`.

#### Known False Positives
Based on the values of`dataPointThreshold` and `deviationThreshold`, the false positive rate may vary. Please modify this according the your environment.

#### Associated Analytic story
* [AWS User Monitoring](/stories/aws_user_monitoring)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_spike_in_security_group_activity.yml) \| *version*: **1**