---
title: "Detect new API calls from user roles"
excerpt: "Cloud Accounts
"
categories:
  - Deprecated
last_modified_at: 2018-04-16
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

This search detects new API calls that have either never been seen before or that have not been seen in the previous hour, where the identity type is `AssumedRole`.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2018-04-16
- **Author**: Bhavin Patel, Splunk
- **ID**: 22773e84-bac0-4595-b086-20d3f335b4f1


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`cloudtrail` eventType=AwsApiCall errorCode=success userIdentity.type=AssumedRole [search `cloudtrail` eventType=AwsApiCall errorCode=success  userIdentity.type=AssumedRole 
| stats earliest(_time) as earliest latest(_time) as latest by userName eventName 
|  inputlookup append=t previously_seen_api_calls_from_user_roles 
| stats min(earliest) as earliest, max(latest) as latest by userName eventName 
| outputlookup previously_seen_api_calls_from_user_roles
| eval newApiCallfromUserRole=if(earliest>=relative_time(now(), "-70m@m"), 1, 0) 
| where newApiCallfromUserRole=1 
| `security_content_ctime(earliest)` 
| `security_content_ctime(latest)` 
| table eventName userName]  
|rename userName as user
| stats values(eventName) earliest(_time) as earliest latest(_time) as latest by user 
| `security_content_ctime(earliest)` 
| `security_content_ctime(latest)` 
| `detect_new_api_calls_from_user_roles_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `detect_new_api_calls_from_user_roles_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_api_calls_from_user_roles](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_api_calls_from_user_roles.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_api_calls_from_user_roles.csv)

#### Required field
* _time
* eventType
* errorCode
* userIdentity.type
* userName
* eventName


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. This search works best when you run the "Previously seen API call per user roles in AWS CloudTrail" support search once to create a history of previously seen user roles.

#### Known False Positives
It is possible that there are legitimate user roles making new or infrequently used API calls in your infrastructure, causing the search to trigger.

#### Associated Analytic story
* [AWS User Monitoring](/stories/aws_user_monitoring)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_new_api_calls_from_user_roles.yml) \| *version*: **1**