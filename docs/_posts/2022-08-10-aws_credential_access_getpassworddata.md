---
title: "AWS Credential Access GetPasswordData"
excerpt: "Unsecured Credentials
"
categories:
  - Cloud
last_modified_at: 2022-08-10
toc: true
toc_label: ""
tags:
  - Unsecured Credentials
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This detection analytic identifies more than 10 GetPasswordData API calls made to your AWS account with a time window of 5 minutes. Attackers can retrieve the encrypted administrator password for a running Windows instance.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-08-10
- **Author**: Bhavin Patel, Splunk
- **ID**: 4d347c4a-306e-41db-8d10-b46baf71b3e2


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | Credential Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
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
`cloudtrail` eventName=GetPasswordData eventSource = ec2.amazonaws.com 
|  bin _time span=5m 
|  stats count values(errorCode) as errorCode dc(requestParameters.instanceId) as distinct_instance_ids values(requestParameters.instanceId) as instance_ids by aws_account_id src_ip user_arn userAgent eventName _time 
|  where distinct_instance_ids > 10 
| `aws_credential_access_getpassworddata_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

> :information_source:
> **aws_credential_access_getpassworddata_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* eventSource
* userIdentity.userName
* userAgent
* userIdentity.accountId
* sourceIPAddress
* awsRegion


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs. We encourage the users to adjust the values of `distinct_instance_ids` and tweak the `span` value according to their environment.

#### Known False Positives
Administrator tooling or automated scripts may make these calls but it is highly unlikely to make several calls in a short period of time.

#### Associated Analytic story
* [AWS Credential Access](/stories/aws_credential_access)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | User $user_arn$ is seen to make mulitple `GetPasswordData` API calls to instance ids $instance_ids$ from IP $src_ip$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)
* [https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-get-password-data/](https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-get-password-data/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552/aws_getpassworddata/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552/aws_getpassworddata/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_credential_access_getpassworddata.yml) \| *version*: **1**