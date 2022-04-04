---
title: "AWS ECR Container Upload Unknown User"
excerpt: "Malicious Image
, User Execution
"
categories:
  - Cloud
last_modified_at: 2021-08-19
toc: true
toc_label: ""
tags:
  - Malicious Image
  - User Execution
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events from AWS Elastic Container Service (ECR). A upload of a new container is normally done from only a few known users. When the user was never seen before, we should have a closer look into the event.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-08-19
- **Author**: Patrick Bareiss, Splunk
- **ID**: 300688e4-365c-4486-a065-7c884462b31d


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1204.003](https://attack.mitre.org/techniques/T1204/003/) | Malicious Image | Execution |

| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

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

* PR.DS
* PR.AC
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 13



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudtrail` eventSource=ecr.amazonaws.com eventName=PutImage NOT `aws_ecr_users` 
| rename requestParameters.* as * 
| rename repositoryName AS image 
| eval phase="release" 
| eval severity="high" 
| stats min(_time) as firstTime max(_time) as lastTime by awsRegion, eventName, eventSource, user, userName, src_ip, imageTag, registryId, image, phase, severity 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_ecr_container_upload_unknown_user_filter`
```

#### Macros
The SPL above uses the following Macros:
* [aws_ecr_users](https://github.com/splunk/security_content/blob/develop/macros/aws_ecr_users.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **aws_ecr_container_upload_unknown_user_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Known False Positives
unknown

#### Associated Analytic story
* [Dev Sec Ops](/stories/dev_sec_ops)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Container uploaded from unknown user $user$ |


#### Reference

* [https://attack.mitre.org/techniques/T1204/003/](https://attack.mitre.org/techniques/T1204/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_ecr_container_upload_unknown_user.yml) \| *version*: **1**