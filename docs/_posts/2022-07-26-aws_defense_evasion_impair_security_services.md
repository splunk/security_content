---
title: "AWS Defense Evasion Impair Security Services"
excerpt: "Disable Cloud Logs
, Impair Defenses
"
categories:
  - Cloud
last_modified_at: 2022-07-26
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

This analytic looks for several delete specific API calls made to AWS Security Services like CloudWatch, GuardDuty and Web Application Firewalls. These API calls are often leveraged by adversaries to weaken existing security defenses by deleting logging configurations in the CloudWatch alarm, delete a set of detectors from your Guardduty environment or simply delete a bunch of CloudWatch alarms to remain stealthy and avoid detection.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-07-26
- **Author**: Bhavin Patel, Gowthamaraj Rajendran, Splunk
- **ID**: b28c4957-96a6-47e0-a965-6c767aac1458


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
`cloudtrail` eventName IN ("DeleteLogStream","DeleteDetector","DeleteIPSet","DeleteWebACL","DeleteRule","DeleteRuleGroup","DeleteLoggingConfiguration","DeleteAlarms") 
| stats count min(_time) as firstTime max(_time) as lastTime values(eventName)  as eventName values(eventSource) as eventSource values(requestParameters.*) as * by src region user_arn aws_account_id user_type user_agent errorCode
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
|  `aws_defense_evasion_impair_security_services_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

> :information_source:
> **aws_defense_evasion_impair_security_services_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* eventSource
* user_agent
* user_type
* aws_account_id
* src
* region
* errorCode


#### How To Implement
You must install Splunk AWS Add on and enable CloudTrail logs in your AWS Environment.

#### Known False Positives
While this search has no known false positives, it is possible that it is a legitimate admin activity. Please consider filtering out these noisy events using userAgent, user_arn field names.

#### Associated Analytic story
* [AWS Defense Evasion](/stories/aws_defense_evasion)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | User $user_arn$ has made potentially risky api calls $eventName$ that could impair AWS security services for account id $aws_account_id$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.aws.amazon.com/cli/latest/reference/guardduty/index.html](https://docs.aws.amazon.com/cli/latest/reference/guardduty/index.html)
* [https://docs.aws.amazon.com/cli/latest/reference/waf/index.html](https://docs.aws.amazon.com/cli/latest/reference/waf/index.html)
* [https://www.elastic.co/guide/en/security/current/prebuilt-rules.html](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/aws_delete_security_services/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/aws_delete_security_services/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_defense_evasion_impair_security_services.yml) \| *version*: **1**