---
title: "AWS ECR Container Upload Outside Business Hours"
excerpt: "Malicious Image, User Execution"
categories:
  - Cloud
last_modified_at: 2021-08-19
toc: true
toc_label: ""
tags:
  - Malicious Image
  - Execution
  - User Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events from AWS Elastic Container Service (ECR). A upload of a new container is normally done during business hours. When done outside business hours, we want to take a look into it.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-08-19
- **Author**: Patrick Bareiss, Splunk
- **ID**: d4c4d4eb-3994-41ca-a25e-a82d64e125bb


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1204.003](https://attack.mitre.org/techniques/T1204/003/) | Malicious Image | Execution |

| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

#### Search

```
`cloudtrail` eventSource=ecr.amazonaws.com eventName=PutImage date_hour>=20 OR date_hour<8 NOT (date_wday=saturday OR date_wday=sunday) 
| rename requestParameters.* as * 
| rename repositoryName AS image 
| eval phase="release" 
| eval severity="medium" 
| stats min(_time) as firstTime max(_time) as lastTime by awsRegion, eventName, eventSource, user, userName, src_ip, imageTag, registryId, image, phase, severity 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_ecr_container_upload_outside_business_hours_filter`
```

#### Associated Analytic Story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Required field
* eventSource
* eventName
* awsRegion
* requestParameters.imageTag
* requestParameters.registryId
* requestParameters.repositoryName
* user
* userName
* src_ip


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
When your development is spreaded in different time zones, applying this rule can be difficult.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Container uploaded outside business hours from $user$ |




#### Reference

* [https://attack.mitre.org/techniques/T1204/003/](https://attack.mitre.org/techniques/T1204/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_ecr_container_upload_outside_business_hours.yml) \| *version*: **1**