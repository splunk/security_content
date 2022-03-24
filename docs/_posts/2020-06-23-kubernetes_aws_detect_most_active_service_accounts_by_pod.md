---
title: "Kubernetes AWS detect most active service accounts by pod"
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

This search provides information on Kubernetes service accounts,accessing pods by IP address, verb and decision

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-06-23
- **Author**: Rod Soto, Splunk
- **ID**: 5b30b25d-7d32-42d8-95ca-64dfcd9076e6

#### Search

```
`aws_cloudwatchlogs_eks` user.groups{}=system:serviceaccounts  objectRef.resource=pods 
| table  sourceIPs{} user.username userAgent verb annotations.authorization.k8s.io/decision  
| top  sourceIPs{} user.username verb annotations.authorization.k8s.io/decision 
|`kubernetes_aws_detect_most_active_service_accounts_by_pod_filter`
```

#### Macros
The SPL above uses the following Macros:
* [aws_cloudwatchlogs_eks](https://github.com/splunk/security_content/blob/develop/macros/aws_cloudwatchlogs_eks.yml)

Note that `kubernetes_aws_detect_most_active_service_accounts_by_pod_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with cloudwatch logs

#### Known False Positives
Not all service accounts interactions are malicious. Analyst must consider IP, verb and decision context when trying to detect maliciousness.

#### Associated Analytic story
* [Kubernetes Sensitive Role Activity](/stories/kubernetes_sensitive_role_activity)


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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_aws_detect_most_active_service_accounts_by_pod.yml) \| *version*: **1**