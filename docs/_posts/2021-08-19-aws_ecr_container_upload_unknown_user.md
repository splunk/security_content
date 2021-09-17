---
title: "AWS ECR Container Upload Unknown User"
excerpt: "Malicious Image"
categories:
  - Cloud
last_modified_at: 2021-08-19
toc: true
tags:
  - Anomaly
  - T1204.003
  - Malicious Image
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---

#### Description

This search looks for AWS CloudTrail events from AWS Elastic Container Service (ECR). A upload of a new container is normally done from only a few known users. When the user was never seen before, we should have a closer look into the event.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **Last Updated**: 2021-08-19
- **Author**: Patrick Bareiss, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1204.003](https://attack.mitre.org/techniques/T1204/003/) | Malicious Image | Execution |


#### Search

```
`cloudtrail` eventSource=ecr.amazonaws.com eventName=PutImage NOT `aws_ecr_users` 
| rename requestParameters.* as * 
| stats min(_time) as firstTime max(_time) as lastTime by awsRegion, eventName, eventSource, user, userName, src_ip, imageTag, registryId, repositoryName 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_ecr_container_upload_unknown_user_filter`
```

#### Associated Analytic Story
* [Dev Sec Ops](_stories/dev_sec_ops)


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
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 49.0 | 70 | 70 |



#### Reference

* [https://attack.mitre.org/techniques/T1204/003/](https://attack.mitre.org/techniques/T1204/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1