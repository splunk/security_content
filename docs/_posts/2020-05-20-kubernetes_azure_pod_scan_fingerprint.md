---
title: "Kubernetes Azure pod scan fingerprint"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2020-05-20
toc: true
toc_label: ""
tags:

  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information of unauthenticated requests via source IP user agent, request URI and response status data against Kubernetes cluster pod in Azure

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-05-20
- **Author**: Rod Soto, Splunk
- **ID**: 86aad3e0-732f-4f66-bbbc-70df448e461d

#### Search

```
`kubernetes_azure` category=kube-audit 
| spath input=properties.log 
| search responseStatus.code=401 
| table  sourceIPs{} userAgent verb requestURI responseStatus.reason properties.pod 
|`kubernetes_azure_pod_scan_fingerprint_filter`
```

#### Macros
The SPL above uses the following Macros:
* [kubernetes_azure](https://github.com/splunk/security_content/blob/develop/macros/kubernetes_azure.yml)

Note that `kubernetes_azure_pod_scan_fingerprint_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install the Add-on for Microsoft Cloud Services and Configure Kube-Audit data diagnostics

#### Known False Positives
Not all unauthenticated requests are malicious, but source IPs, userAgent, verb, request URI and response status will provide context.

#### Associated Analytic story
* [Kubernetes Scanning Activity](/stories/kubernetes_scanning_activity)


#### Kill Chain Phase
* Reconnaissance



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_azure_pod_scan_fingerprint.yml) \| *version*: **1**