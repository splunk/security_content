---
title: "Detect Spike in Network ACL Activity"
excerpt: "Disable or Modify Cloud Firewall
"
categories:
  - Deprecated
last_modified_at: 2018-05-21
toc: true
toc_label: ""
tags:
  - Disable or Modify Cloud Firewall
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search will detect users creating spikes in API activity related to network access-control lists (ACLs)in your AWS environment. This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2018-05-21
- **Author**: Bhavin Patel, Splunk
- **ID**: ada0f478-84a8-4641-a1f1-e32372d4bd53


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Disable or Modify Cloud Firewall | Defense Evasion |

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

* CIS 12
* CIS 11



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudtrail` `network_acl_events` [search `cloudtrail` `network_acl_events` 
| spath output=arn path=userIdentity.arn 
| stats count as apiCalls by arn 
| inputlookup network_acl_activity_baseline append=t 
| fields - latestCount 
| stats values(*) as * by arn 
| rename apiCalls as latestCount 
| eval newAvgApiCalls=avgApiCalls + (latestCount-avgApiCalls)/720 
| eval newStdevApiCalls=sqrt(((pow(stdevApiCalls, 2)*719 + (latestCount-newAvgApiCalls)*(latestCount-avgApiCalls))/720)) 
| eval avgApiCalls=coalesce(newAvgApiCalls, avgApiCalls), stdevApiCalls=coalesce(newStdevApiCalls, stdevApiCalls), numDataPoints=if(isnull(latestCount), numDataPoints, numDataPoints+1) 
| table arn, latestCount, numDataPoints, avgApiCalls, stdevApiCalls 
| outputlookup network_acl_activity_baseline 
| eval dataPointThreshold = 15, deviationThreshold = 3 
| eval isSpike=if((latestCount > avgApiCalls+deviationThreshold*stdevApiCalls) AND numDataPoints > dataPointThreshold, 1, 0) 
| where isSpike=1 
| rename arn as userIdentity.arn 
| table userIdentity.arn] 
| spath output=user userIdentity.arn 
| stats values(eventName) as eventNames, count as numberOfApiCalls, dc(eventName) as uniqueApisCalled by user 
| `detect_spike_in_network_acl_activity_filter`
```

#### Macros
The SPL above uses the following Macros:
* [network_acl_events](https://github.com/splunk/security_content/blob/develop/macros/network_acl_events.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that **detect_spike_in_network_acl_activity_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [network_acl_activity_baseline](https://github.com/splunk/security_content/blob/develop/lookups/network_acl_activity_baseline.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/network_acl_activity_baseline.csv)
* [network_acl_activity_baseline](https://github.com/splunk/security_content/blob/develop/lookups/network_acl_activity_baseline.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/network_acl_activity_baseline.csv)

#### Required field
* _time
* userIdentity.arn


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. You can modify `dataPointThreshold` and `deviationThreshold` to better fit your environment. The `dataPointThreshold` variable is the minimum number of data points required to have a statistically significant amount of data to determine. The `deviationThreshold` variable is the number of standard deviations away from the mean that the value must be to be considered a spike. This search works best when you run the "Baseline of Network ACL Activity by ARN" support search once to create a lookup file of previously seen Network ACL Activity. To add or remove API event names related to network ACLs, edit the macro `network_acl_events`.

#### Known False Positives
The false-positive rate may vary based on the values of`dataPointThreshold` and `deviationThreshold`. Please modify this according the your environment.

#### Associated Analytic story
* [AWS Network ACL Activity](/stories/aws_network_acl_activity)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_spike_in_network_acl_activity.yml) \| *version*: **1**