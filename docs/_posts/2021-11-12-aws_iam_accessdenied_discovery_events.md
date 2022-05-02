---
title: "AWS IAM AccessDenied Discovery Events"
excerpt: "Cloud Infrastructure Discovery
"
categories:
  - Cloud
last_modified_at: 2021-11-12
toc: true
toc_label: ""
tags:
  - Cloud Infrastructure Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following detection identifies excessive AccessDenied events within an hour timeframe. It is possible that an access key to AWS may have been stolen and is being misused to perform discovery events. In these instances, the access is not available with the key stolen therefore these events will be generated.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-11-12
- **Author**: Michael Haag, Splunk
- **ID**: 3e1f1568-9633-11eb-a69c-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1580](https://attack.mitre.org/techniques/T1580/) | Cloud Infrastructure Discovery | Discovery |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudtrail` (errorCode = "AccessDenied") user_type=IAMUser (userAgent!=*.amazonaws.com) 
| bucket _time span=1h 
| stats count as failures min(_time) as firstTime max(_time) as lastTime, dc(eventName) as methods, dc(eventSource) as sources by src_ip, userIdentity.arn, _time 
| where failures >= 5 and methods >= 1 and sources >= 1 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_iam_accessdenied_discovery_events_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **aws_iam_accessdenied_discovery_events_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* eventSource
* userAgent
* errorCode
* userIdentity.type


#### How To Implement
The Splunk AWS Add-on and Splunk App for AWS is required to utilize this data. The search requires AWS Cloudtrail logs.

#### Known False Positives
It is possible to start this detection will need to be tuned by source IP or user. In addition, change the count values to an upper threshold to restrict false positives.

#### Associated Analytic story
* [Suspicious Cloud User Activities](/stories/suspicious_cloud_user_activities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 10.0 | 20 | 50 | User $userIdentity.arn$ is seen to perform excessive number of discovery related api calls- $failures$, within an hour where the access was denied. |


#### Reference

* [https://aws.amazon.com/premiumsupport/knowledge-center/troubleshoot-iam-permission-errors/](https://aws.amazon.com/premiumsupport/knowledge-center/troubleshoot-iam-permission-errors/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/aws_iam_accessdenied_discovery_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/aws_iam_accessdenied_discovery_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_iam_accessdenied_discovery_events.yml) \| *version*: **2**