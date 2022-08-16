---
title: "AWS Credential Access RDS Password reset"
excerpt: "Password Cracking
"
categories:
  - Cloud
last_modified_at: 2022-08-07
toc: true
toc_label: ""
tags:
  - Password Cracking
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The master user password for Amazon RDS DB instance can be reset using the Amazon RDS console. Using this technique, the attacker can get access to the sensitive data from the DB. Usually, the production databases may have sensitive data like Credit card information, PII, Health care Data. This event should be investigated further.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-08-07
- **Author**: Gowthamaraj Rajendran, Splunk
- **ID**: 6153c5ea-ed30-4878-81e6-21ecdb198189


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1110.002](https://attack.mitre.org/techniques/T1110/002/) | Password Cracking | Credential Access |

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
`cloudtrail` eventSource="rds.amazonaws.com" eventName=ModifyDBInstance "requestParameters.masterUserPassword"=* 
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.dBInstanceIdentifier) as DB by sourceIPAddress awsRegion eventName userAgent
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `aws_credential_access_rds_password_reset_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **aws_credential_access_rds_password_reset_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* eventSource
* requestParameters.dBInstanceIdentifier
* userAgent
* sourceIPAddress
* awsRegion


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Known False Positives
Users may genuinely reset the RDS password.

#### Associated Analytic story
* [AWS Credential Access](/stories/aws_credential_access)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | $DB$ password has been reset from IP $sourceIPAddress$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://aws.amazon.com/premiumsupport/knowledge-center/reset-master-user-password-rds](https://aws.amazon.com/premiumsupport/knowledge-center/reset-master-user-password-rds)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.002/aws_rds_password_reset/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.002/aws_rds_password_reset/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_credential_access_rds_password_reset.yml) \| *version*: **1**