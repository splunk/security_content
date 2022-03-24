---
title: "Kubernetes AWS detect service accounts forbidden failure access"
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

This search provides information on Kubernetes service accounts with failure or forbidden access status, this search can be extended by using top or rare operators to find trends or rarities in failure status, user agents, source IPs and request URI

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-06-23
- **Author**: Rod Soto, Splunk
- **ID**: a6959c57-fa8f-4277-bb86-7c32fba579d5

#### Search

```
`aws_cloudwatchlogs_eks` user.groups{}=system:serviceaccounts responseStatus.status = Failure 
| table sourceIPs{} user.username userAgent verb responseStatus.status requestURI 
| `kubernetes_aws_detect_service_accounts_forbidden_failure_access_filter`
```

#### Macros
The SPL above uses the following Macros:
* [aws_cloudwatchlogs_eks](https://github.com/splunk/security_content/blob/develop/macros/aws_cloudwatchlogs_eks.yml)

Note that `kubernetes_aws_detect_service_accounts_forbidden_failure_access_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with cloudwatch logs.

#### Known False Positives
This search can give false positives as there might be inherent issues with authentications and permissions at cluster.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_aws_detect_service_accounts_forbidden_failure_access.yml) \| *version*: **1**