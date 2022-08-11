---
title: "AWS Defense Evasion Update Cloudtrail"
excerpt: "Impair Defenses
, Disable Cloud Logs
"
categories:
  - Cloud
last_modified_at: 2022-07-17
toc: true
toc_label: ""
tags:
  - Impair Defenses
  - Disable Cloud Logs
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies `UpdateTrail` events in CloudTrail logs. Attackers may evade the logging capability by updating the settings and impairing them with wrong parameters. For example, Attackers may change the multi-regional log into a single region logs, which evades the logging for other regions. When the adversary has the right type of permissions in the compromised AWS environment, they may update the CloudTrail settings that is logging activities in your environment.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-07-17
- **Author**: Gowthamaraj Rajendran, Splunk
- **ID**: 7c921d28-ef48-4f1b-85b3-0af8af7697db


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

| [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | Disable Cloud Logs | Defense Evasion |

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
`cloudtrail` eventName = UpdateTrail eventSource = cloudtrail.amazonaws.com userAgent !=console.amazonaws.com errorCode = success
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.name) as cloudtrail_name by src region eventName userAgent user_arn aws_account_id 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `aws_defense_evasion_update_cloudtrail_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

> :information_source:
> **aws_defense_evasion_update_cloudtrail_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
You must install Splunk AWS Add on and enable CloudTrail logs in your AWS Environment.

#### Known False Positives
While this search has no known false positives, it is possible that an AWS admin has updated cloudtrail logging. Please investigate this activity.

#### Associated Analytic story
* [AWS Defense Evasion](/stories/aws_defense_evasion)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 100 | 90 | User $user_arn$ has updated a cloudtrail logging for account id $aws_account_id$ from IP $src$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1562/008/](https://attack.mitre.org/techniques/T1562/008/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/update_cloudtrail/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/update_cloudtrail/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_defense_evasion_update_cloudtrail.yml) \| *version*: **1**