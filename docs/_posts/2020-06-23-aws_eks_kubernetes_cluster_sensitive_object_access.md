---
title: "AWS EKS Kubernetes cluster sensitive object access"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2020-06-23
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information on Kubernetes accounts accessing sensitve objects such as configmaps or secrets

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-06-23
- **Author**: Rod Soto, Splunk
- **ID**: 7f227943-2196-4d4d-8d6a-ac8cb308e61c


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

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
`aws_cloudwatchlogs_eks` objectRef.resource=secrets OR configmaps sourceIPs{}!=::1 sourceIPs{}!=127.0.0.1  
|table sourceIPs{} user.username user.groups{} objectRef.resource objectRef.namespace objectRef.name annotations.authorization.k8s.io/reason 
|dedup user.username user.groups{} 
|`aws_eks_kubernetes_cluster_sensitive_object_access_filter`
```

#### Macros
The SPL above uses the following Macros:
* [aws_cloudwatchlogs_eks](https://github.com/splunk/security_content/blob/develop/macros/aws_cloudwatchlogs_eks.yml)

Note that **aws_eks_kubernetes_cluster_sensitive_object_access_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install Splunk Add-on for Amazon Web Services and Splunk App for AWS. This search works with cloudwatch logs.

#### Known False Positives
Sensitive object access is not necessarily malicious but user and object context can provide guidance for detection.

#### Associated Analytic story
* [Kubernetes Sensitive Object Access Activity](/stories/kubernetes_sensitive_object_access_activity)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/aws_eks_kubernetes_cluster_sensitive_object_access.yml) \| *version*: **1**