---
title: "AWS Lambda UpdateFunctionCode"
excerpt: "User Execution
"
categories:
  - Cloud
last_modified_at: 2022-02-24
toc: true
toc_label: ""
tags:
  - User Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is designed to detect IAM users attempting to update/modify AWS lambda code via the AWS CLI to gain persistence, futher access into your AWS environment and to facilitate planting backdoors. In this instance, an attacker may upload malicious code/binary to a lambda function which will be executed automatically when the funnction is triggered.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-02-24
- **Author**: Bhavin Patel, Splunk
- **ID**: 211b80d3-6340-4345-11ad-212bf3d0d111


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
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
`cloudtrail` eventSource=lambda.amazonaws.com eventName=UpdateFunctionCode*  errorCode = success  user_type=IAMUser 
| stats  count min(_time) as firstTime max(_time) as lastTime  values(requestParameters.functionName) as function_updated by src_ip user_arn user_agent user_type eventName aws_account_id 
|`aws_lambda_updatefunctioncode_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that **aws_lambda_updatefunctioncode_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* userAgent
* errorCode


#### How To Implement
You must install Splunk AWS Add on and enable Cloudtrail logs in your AWS Environment.

#### Known False Positives
While this search has no known false positives, it is possible that an AWS admin or an autorized IAM user has updated the lambda fuction code legitimately.

#### Associated Analytic story
* [Suspicious Cloud User Activities](/stories/suspicious_cloud_user_activities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | User $user_arn$ is attempting to update the lambda function code of $function_updated$ from this IP $src_ip$ |


#### Reference

* [http://detectioninthe.cloud/execution/modify_lambda_function_code/](http://detectioninthe.cloud/execution/modify_lambda_function_code/)
* [https://sysdig.com/blog/exploit-mitigate-aws-lambdas-mitre/](https://sysdig.com/blog/exploit-mitigate-aws-lambdas-mitre/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204/aws_updatelambdafunctioncode/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204/aws_updatelambdafunctioncode/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_lambda_updatefunctioncode.yml) \| *version*: **1**