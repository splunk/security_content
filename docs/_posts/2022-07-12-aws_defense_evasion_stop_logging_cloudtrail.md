---
title: "AWS Defense Evasion Stop Logging Cloudtrail"
excerpt: "Disable Cloud Logs
, Impair Defenses
"
categories:
  - Cloud
last_modified_at: 2022-07-12
toc: true
toc_label: ""
tags:
  - Disable Cloud Logs
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies `StopLogging` events in CloudTrail logs. Adversaries often try to impair their target's defenses by stopping their macliious activity from being logged, so that they may operate with stealth and avoid detection. When the adversary has the right type of permissions in the compromised AWS environment, they may easily stop logging.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-07-12
- **Author**: Bhavin Patel, Splunk
- **ID**: 8a2f3ca2-4eb5-4389-a549-14063882e537


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | Disable Cloud Logs | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

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
`cloudtrail` eventName = StopLogging eventSource = cloudtrail.amazonaws.com userAgent !=console.amazonaws.com errorCode = success
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.name) as stopped_cloudtrail_name by src region eventName userAgent user_arn aws_account_id 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `aws_defense_evasion_stop_logging_cloudtrail_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **aws_defense_evasion_stop_logging_cloudtrail_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* eventSource
* requestParameters.name
* userAgent
* aws_account_id
* src
* region


#### How To Implement
You must install Splunk AWS Add on and enable Cloudtrail logs in your AWS Environment.

#### Known False Positives
While this search has no known false positives, it is possible that an AWS admin has stopped cloudtrail logging. Please investigate this activity.

#### Associated Analytic story
* [AWS Defense Evasion](/stories/aws_defense_evasion)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 100 | 90 | User $user_arn$ has stopped Cloudtrail logging for account id $aws_account_id$ from IP $src$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1562/008/](https://attack.mitre.org/techniques/T1562/008/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/stop_delete_cloudtrail/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/stop_delete_cloudtrail/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_defense_evasion_stop_logging_cloudtrail.yml) \| *version*: **1**