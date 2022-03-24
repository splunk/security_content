---
title: "Kubernetes AWS detect suspicious kubectl calls"
excerpt: ""
categories:
  - Cloud
last_modified_at: 2020-06-23
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information on anonymous Kubectl calls with IP, verb namespace and object access context

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-06-23
- **Author**: Rod Soto, Splunk
- **ID**: 042a3d32-8318-4763-9679-09db2644a8f2

#### Search

```
`aws_cloudwatchlogs_eks` userAgent=kubectl* sourceIPs{}!=127.0.0.1 sourceIPs{}!=::1 src_user=system:anonymous  
| table  src_ip src_user verb userAgent requestURI  
| stats  count by src_ip src_user verb userAgent requestURI 
|`kubernetes_aws_detect_suspicious_kubectl_calls_filter`
```

#### Macros
The SPL above uses the following Macros:
* [aws_cloudwatchlogs_eks](https://github.com/splunk/security_content/blob/develop/macros/aws_cloudwatchlogs_eks.yml)

Note that `kubernetes_aws_detect_suspicious_kubectl_calls_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* userAgent
* sourceIPs{}
* src_user
* src_ip
* verb
* requestURI


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with cloudwatch logs.

#### Known False Positives
Kubectl calls are not malicious by nature. However source IP, verb and Object can reveal potential malicious activity, specially anonymous suspicious IPs and sensitive objects such as configmaps or secrets

#### Associated Analytic story
* [Kubernetes Sensitive Object Access Activity](/stories/kubernetes_sensitive_object_access_activity)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/kubernetes_aws_detect_suspicious_kubectl_calls.yml) \| *version*: **1**