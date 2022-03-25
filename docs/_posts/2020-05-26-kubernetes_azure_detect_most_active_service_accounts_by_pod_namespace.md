---
title: "Kubernetes Azure detect most active service accounts by pod namespace"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information on Kubernetes service accounts,accessing pods and namespaces by IP address and verb

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-05-26
- **Author**: Rod Soto, Splunk
- **ID**: 55a2264a-b7f0-45e5-addd-1e5ab3415c72

#### Search

```
`kubernetes_azure` category=kube-audit 
| spath input=properties.log 
| search user.groups{}=system:serviceaccounts* OR user.username=system.anonymous OR annotations.authorization.k8s.io/decision=allow  
| table  sourceIPs{} user.username userAgent verb responseStatus.reason responseStatus.status properties.pod objectRef.namespace 
| top sourceIPs{} user.username verb responseStatus.status properties.pod objectRef.namespace 
|`kubernetes_azure_detect_most_active_service_accounts_by_pod_namespace_filter`
```

#### Macros
The SPL above uses the following Macros:
* [kubernetes_azure](https://github.com/splunk/security_content/blob/develop/macros/kubernetes_azure.yml)

Note that `kubernetes_azure_detect_most_active_service_accounts_by_pod_namespace_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install the Add-on for Microsoft Cloud Services and Configure Kube-Audit data diagnostics

#### Known False Positives
Not all service accounts interactions are malicious. Analyst must consider IP and verb context when trying to detect maliciousness.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_azure_detect_most_active_service_accounts_by_pod_namespace.yml) \| *version*: **1**