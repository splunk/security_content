---
title: "Kubernetes Azure detect sensitive role access"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information on Kubernetes accounts accessing sensitve objects such as configmpas or secrets

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-05-20
- **Author**: Rod Soto, Splunk
- **ID**: f27349e5-1641-4f6a-9e68-30402be0ad4c

#### Search

```
`kubernetes_azure` category=kube-audit 
| spath input=properties.log
| search objectRef.resource=clusterroles OR clusterrolebindings 
| table sourceIPs{} user.username user.groups{} objectRef.namespace requestURI annotations.authorization.k8s.io/reason 
| dedup user.username user.groups{} 
|`kubernetes_azure_detect_sensitive_role_access_filter`
```

#### Macros
The SPL above uses the following Macros:
* [kubernetes_azure](https://github.com/splunk/security_content/blob/develop/macros/kubernetes_azure.yml)

Note that `kubernetes_azure_detect_sensitive_role_access_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install the Add-on for Microsoft Cloud Services and Configure Kube-Audit data diagnostics

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_azure_detect_sensitive_role_access.yml) \| *version*: **1**