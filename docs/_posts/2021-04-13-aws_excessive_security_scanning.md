---
title: "AWS Excessive Security Scanning"
excerpt: "Cloud Service Discovery
"
categories:
  - Cloud
last_modified_at: 2021-04-13
toc: true
toc_label: ""
tags:
  - Cloud Service Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events and analyse the amount of eventNames which starts with Describe by a single user. This indicates that this user scans the configuration of your AWS cloud environment.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-04-13
- **Author**: Patrick Bareiss, Splunk
- **ID**: 1fdd164a-def8-4762-83a9-9ffe24e74d5a


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1526](https://attack.mitre.org/techniques/T1526/) | Cloud Service Discovery | Discovery |

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
`cloudtrail` eventName=Describe* OR eventName=List* OR eventName=Get*  
| stats dc(eventName) as dc_events min(_time) as firstTime max(_time) as lastTime values(eventName) as eventName values(src) as src values(userAgent) as userAgent by user userIdentity.arn 
| where dc_events > 50 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
|`aws_excessive_security_scanning_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

> :information_source:
> **aws_excessive_security_scanning_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* src
* userAgent
* user
* userIdentity.arn


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Known False Positives
While this search has no known false positives.

#### Associated Analytic story
* [AWS User Monitoring](/stories/aws_user_monitoring)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 18.0 | 30 | 60 | user $user$ has excessive number of api calls $dc_events$ from these IP addresses $src$, violating the threshold of 50,  using the following commands $command$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://github.com/aquasecurity/cloudsploit](https://github.com/aquasecurity/cloudsploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_excessive_security_scanning.yml) \| *version*: **1**