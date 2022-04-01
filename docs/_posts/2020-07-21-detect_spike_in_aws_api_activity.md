---
title: "Detect Spike in AWS API Activity"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search will detect users creating spikes of API activity in your AWS environment.  It will also update the cache file that factors in the latest data. This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk
- **ID**: ada0f478-84a8-4641-a3f1-d32362d4bd55


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
* DE.CM
* PR.AC



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

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
`cloudtrail` eventType=AwsApiCall [search `cloudtrail` eventType=AwsApiCall 
| spath output=arn path=userIdentity.arn 
| stats count as apiCalls by arn 
| inputlookup api_call_by_user_baseline append=t 
| fields - latestCount 
| stats values(*) as * by arn 
| rename apiCalls as latestCount 
| eval newAvgApiCalls=avgApiCalls + (latestCount-avgApiCalls)/720 
| eval newStdevApiCalls=sqrt(((pow(stdevApiCalls, 2)*719 + (latestCount-newAvgApiCalls)*(latestCount-avgApiCalls))/720)) 
| eval avgApiCalls=coalesce(newAvgApiCalls, avgApiCalls), stdevApiCalls=coalesce(newStdevApiCalls, stdevApiCalls), numDataPoints=if(isnull(latestCount), numDataPoints, numDataPoints+1) 
| table arn, latestCount, numDataPoints, avgApiCalls, stdevApiCalls 
| outputlookup api_call_by_user_baseline 
| eval dataPointThreshold = 15, deviationThreshold = 3 
| eval isSpike=if((latestCount > avgApiCalls+deviationThreshold*stdevApiCalls) AND numDataPoints > dataPointThreshold, 1, 0) 
| where isSpike=1 
| rename arn as userIdentity.arn 
| table userIdentity.arn] 
| spath output=user userIdentity.arn 
| stats values(eventName) as eventName, count as numberOfApiCalls, dc(eventName) as uniqueApisCalled by user 
| `detect_spike_in_aws_api_activity_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that **detect_spike_in_aws_api_activity_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [api_call_by_user_baseline](https://github.com/splunk/security_content/blob/develop/lookups/api_call_by_user_baseline.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/api_call_by_user_baseline.csv)
* [api_call_by_user_baseline](https://github.com/splunk/security_content/blob/develop/lookups/api_call_by_user_baseline.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/api_call_by_user_baseline.csv)

#### Required field
* _time
* eventType
* userIdentity.arn


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. You can modify `dataPointThreshold` and `deviationThreshold` to better fit your environment. The `dataPointThreshold` variable is the minimum number of data points required to have a statistically significant amount of data to determine. The `deviationThreshold` variable is the number of standard deviations away from the mean that the value must be to be considered a spike.\
This search produces fields (`eventName`,`numberOfApiCalls`,`uniqueApisCalled`) that are not yet supported by ES Incident Review and therefore cannot be viewed when a notable event is raised. These fields contribute additional context to the notable. To see the additional metadata, add the following fields, if not already present, to Incident Review - Event Attributes (Configure > Incident Management > Incident Review Settings > Add New Entry):\\n1. **Label:** AWS Event Name, **Field:** eventName\
1. \
1. **Label:** Number of API Calls, **Field:** numberOfApiCalls\
1. \
1. **Label:** Unique API Calls, **Field:** uniqueApisCalled\
Detailed documentation on how to create a new field within Incident Review may be found here: `https://docs.splunk.com/Documentation/ES/5.3.0/Admin/Customizenotables#Add_a_field_to_the_notable_event_details`

#### Known False Positives


#### Associated Analytic story
* [AWS User Monitoring](/stories/aws_user_monitoring)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_spike_in_aws_api_activity.yml) \| *version*: **2**