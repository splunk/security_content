---
title: "AWS ECR Container Scanning Findings Low Informational Unknown"
excerpt: "Malicious Image"
categories:
  - Cloud
last_modified_at: 2021-08-17
toc: true
tags:
  - Hunting
  - T1204.003
  - Malicious Image
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events from AWS Elastic Container Service (ECR). You need to activate image scanning in order to get the event DescribeImageScanFindings with the results.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-08-17
- **Author**: Patrick Bareiss, Splunk
- **ID**: cbc95e44-7c22-443f-88fd-0424478f5589


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1204.003](https://attack.mitre.org/techniques/T1204/003/) | Malicious Image | Execution |


#### Search

```
`cloudtrail` eventSource=ecr.amazonaws.com eventName=DescribeImageScanFindings 
| spath path=responseElements.imageScanFindings.findings{} output=findings 
| mvexpand findings 
| spath input=findings
| search severity IN (LOW, INFORMATIONAL, UNKNWON) 
| rename name as finding_name, description as finding_description, requestParameters.imageId.imageDigest as imageDigest, requestParameters.repositoryName as repositoryName 
| eval finding = finding_name.", ".finding_description 
| eval phase="release" 
| eval severity="low" 
| stats min(_time) as firstTime max(_time) as lastTime by awsRegion, eventName, eventSource, imageDigest, repositoryName, user, userName, src_ip, finding, phase, severity 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_ecr_container_scanning_findings_low_informational_unknown_filter`
```

#### Associated Analytic Story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Required field
* eventSource
* eventName
* responseElements.imageScanFindings.findings{}
* awsRegion
* requestParameters.imageId.imageDigest
* requestParameters.repositoryName
* user
* userName
* src_ip


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 7.0 | 10 | 70 | Vulnerabilities with severity high found in repository $repositoryName$ |



#### Reference

* [https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_ecr_container_scanning_findings_low_informational_unknown.yml) \| *version*: **1**