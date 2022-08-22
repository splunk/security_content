---
title: "AWS Credential Access Failed Login"
excerpt: "Password Guessing
"
categories:
  - Cloud
last_modified_at: 2022-08-07
toc: true
toc_label: ""
tags:
  - Password Guessing
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

It shows that there have been an unsuccessful attempt to log in using the user identity to the AWS management console. Since the user identity has access to AWS account services and resources, an attacker might try to brute force the password for that identity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2022-08-07
- **Author**: Gowthamaraj Rajendran, Bhavin Patel, Splunk
- **ID**: a19b354d-0d7f-47f3-8ea6-1a7c36434968


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Credential Access |

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

| tstats count earliest(_time) as firstTime, latest(_time) as lastTime from datamodel=Authentication where Authentication.action = failure Authentication.app=AwsConsoleSignIn Authentication.signature=ConsoleLogin BY Authentication.app Authentication.signature Authentication.dest  Authentication.user Authentication.action Authentication.user_id Authentication.src 
| `drop_dm_object_name(Authentication)`  
| `security_content_ctime(firstTime)`
|  `security_content_ctime(lastTime)` 
| `aws_credential_access_failed_login_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **aws_credential_access_failed_login_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* app
* eventSource
* action
* signature
* dest
* user
* user_id


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Known False Positives
Users may genuinely mistype or forget the password.

#### Associated Analytic story
* [AWS Credential Access](/stories/aws_credential_access)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | User $user$ has a login failure from IP $src$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1110/001/](https://attack.mitre.org/techniques/T1110/001/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/aws_login_failure/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/aws_login_failure/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_credential_access_failed_login.yml) \| *version*: **1**