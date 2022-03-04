---
title: "Kubernetes AWS detect sensitive role access"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information on Kubernetes accounts accessing sensitve objects such as configmpas or secrets

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-06-23
- **Author**: Rod Soto, Splunk
- **ID**: b6013a7b-85e0-4a45-b051-10b252d69569

#### Search

```
`aws_cloudwatchlogs_eks` objectRef.resource=clusterroles OR clusterrolebindings sourceIPs{}!=::1 sourceIPs{}!=127.0.0.1  
| table sourceIPs{} user.username user.groups{} objectRef.namespace requestURI annotations.authorization.k8s.io/reason 
| dedup user.username user.groups{} 
|`kubernetes_aws_detect_sensitive_role_access_filter`
```

#### Macros
The SPL above uses the following Macros:
* [aws_cloudwatchlogs_eks](https://github.com/splunk/security_content/blob/develop/macros/aws_cloudwatchlogs_eks.yml)

Note that `kubernetes_aws_detect_sensitive_role_access_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with cloudwatch logs.

#### Known False Positives
Sensitive role resource access is necessary for cluster operation, however source IP, namespace and user group may indicate possible malicious use. 

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_aws_detect_sensitive_role_access.yml) \| *version*: **1**