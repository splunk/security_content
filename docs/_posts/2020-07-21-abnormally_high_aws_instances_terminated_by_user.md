---
title: "Abnormally High AWS Instances Terminated by User"
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

This search looks for AWS CloudTrail events where an abnormally high number of instances were successfully terminated by a user in a 10-minute window. This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 8d301246-fccf-45e2-a8e7-3655fd14379c


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`cloudtrail` eventName=TerminateInstances errorCode=success 
| bucket span=10m _time 
| stats count AS instances_terminated by _time userName 
| eventstats avg(instances_terminated) as total_terminations_avg, stdev(instances_terminated) as total_terminations_stdev 
| eval threshold_value = 4 
| eval isOutlier=if(instances_terminated > total_terminations_avg+(total_terminations_stdev * threshold_value), 1, 0) 
| search isOutlier=1 AND _time >= relative_time(now(), "-10m@m")
| eval num_standard_deviations_away = round(abs(instances_terminated - total_terminations_avg) / total_terminations_stdev, 2) 
|table _time, userName, instances_terminated, num_standard_deviations_away, total_terminations_avg, total_terminations_stdev 
| `abnormally_high_aws_instances_terminated_by_user_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `abnormally_high_aws_instances_terminated_by_user_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* errorCode
* userName


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs.

#### Known False Positives
Many service accounts configured with your AWS infrastructure are known to exhibit this behavior. Please adjust the threshold values and filter out service accounts from the output. Always verify whether this search alerted on a human user.

#### Associated Analytic story
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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/abnormally_high_aws_instances_terminated_by_user.yml) \| *version*: **2**