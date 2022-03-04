---
title: "Abnormally High AWS Instances Launched by User - MLTK"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events where a user successfully launches an abnormally high number of instances. This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-21
- **Author**: Jason Brewer, Splunk
- **ID**: dec41ad5-d579-42cb-b4c6-f5dbb778bbe5


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`cloudtrail` eventName=RunInstances errorCode=success `abnormally_high_aws_instances_launched_by_user___mltk_filter` 
| bucket span=10m _time  
| stats count as instances_launched by _time src_user  
| apply ec2_excessive_runinstances_v1  
| rename "IsOutlier(instances_launched)" as isOutlier  
| where isOutlier=1
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `abnormally_high_aws_instances_launched_by_user_-_mltk_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* errorCode
* src_user


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. The threshold value should be tuned to your environment.

#### Known False Positives
Many service accounts configured within an AWS infrastructure are known to exhibit this behavior. Please adjust the threshold values and filter out service accounts from the output. Always verify if this search alerted on a human user.

#### Associated Analytic story
* [AWS Cryptomining](/stories/aws_cryptomining)
* [Suspicious AWS EC2 Activities](/stories/suspicious_aws_ec2_activities)


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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/abnormally_high_aws_instances_launched_by_user_-_mltk.yml) \| *version*: **2**