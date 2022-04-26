---
title: "Amazon EKS Kubernetes cluster scan detection"
excerpt: "Cloud Service Discovery
"
categories:
  - Cloud
last_modified_at: 2020-04-15
toc: true
toc_label: ""
tags:
  - Cloud Service Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information of unauthenticated requests via user agent, and authentication data against Kubernetes cluster in AWS

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-04-15
- **Author**: Rod Soto, Splunk
- **ID**: 294c4686-63dd-4fe6-93a2-ca807626704a


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
`aws_cloudwatchlogs_eks` "user.username"="system:anonymous" userAgent!="AWS Security Scanner" 
| rename sourceIPs{} as src_ip 
| stats count min(_time) as firstTime max(_time) as lastTime values(responseStatus.reason) values(source) as cluster_name values(responseStatus.code) values(userAgent) as http_user_agent values(verb) values(requestURI) by src_ip user.username user.groups{} 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
|`amazon_eks_kubernetes_cluster_scan_detection_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [aws_cloudwatchlogs_eks](https://github.com/splunk/security_content/blob/develop/macros/aws_cloudwatchlogs_eks.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **amazon_eks_kubernetes_cluster_scan_detection_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* user.username
* userAgent
* sourceIPs{}
* responseStatus.reason
* source
* responseStatus.code
* verb
* requestURI
* src_ip
* user.groups{}


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your CloudWatch EKS Logs inputs.

#### Known False Positives
Not all unauthenticated requests are malicious, but frequency, UA and source IPs will provide context.

#### Associated Analytic story
* [Kubernetes Scanning Activity](/stories/kubernetes_scanning_activity)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/amazon_eks_kubernetes_cluster_scan_detection.yml) \| *version*: **1**