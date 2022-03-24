---
title: "Kubernetes Azure detect suspicious kubectl calls"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2020-05-26
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information on rare Kubectl calls with IP, verb namespace and object access context

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-05-26
- **Author**: Rod Soto, Splunk
- **ID**: 4b6d1ba8-0000-4cec-87e6-6cbbd71651b5

#### Search

```
`kubernetes_azure` category=kube-audit 
| spath input=properties.log 
| spath input=responseObject.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration 
| search userAgent=kubectl* sourceIPs{}!=127.0.0.1 sourceIPs{}!=::1 
| table sourceIPs{} verb userAgent user.groups{} objectRef.resource objectRef.namespace requestURI 
| rare sourceIPs{} verb userAgent user.groups{} objectRef.resource objectRef.namespace requestURI 
|`kubernetes_azure_detect_suspicious_kubectl_calls_filter`
```

#### Macros
The SPL above uses the following Macros:
* [kubernetes_azure](https://github.com/splunk/security_content/blob/develop/macros/kubernetes_azure.yml)

Note that `kubernetes_azure_detect_suspicious_kubectl_calls_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install the Add-on for Microsoft Cloud Services and Configure Kube-Audit data diagnostics

#### Known False Positives
Kubectl calls are not malicious by nature. However source IP, verb and Object can reveal potential malicious activity, specially suspicious IPs and sensitive objects such as configmaps or secrets

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_azure_detect_suspicious_kubectl_calls.yml) \| *version*: **1**