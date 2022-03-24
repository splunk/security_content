---
title: "Kubernetes Azure detect sensitive object access"
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
- **ID**: 1bba382b-07fd-4ffa-b390-8002739b76e8

#### Search

```
`kubernetes_azure` category=kube-audit 
| spath input=properties.log
| search objectRef.resource=secrets OR configmaps user.username=system.anonymous OR annotations.authorization.k8s.io/decision=allow  
|table user.username user.groups{} objectRef.resource objectRef.namespace objectRef.name annotations.authorization.k8s.io/reason 
|dedup user.username user.groups{} 
|`kubernetes_azure_detect_sensitive_object_access_filter`
```

#### Macros
The SPL above uses the following Macros:
* [kubernetes_azure](https://github.com/splunk/security_content/blob/develop/macros/kubernetes_azure.yml)

Note that `kubernetes_azure_detect_sensitive_object_access_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install the Add-on for Microsoft Cloud Services and Configure Kube-Audit data diagnostics

#### Known False Positives
Sensitive object access is not necessarily malicious but user and object context can provide guidance for detection.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_azure_detect_sensitive_object_access.yml) \| *version*: **1**