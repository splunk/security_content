---
title: "Kubernetes GCP detect sensitive object access"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2020-07-11
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

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-07-11
- **Author**: Rod Soto, Splunk
- **ID**: bdb6d596-86a0-4aba-8369-418ae8b9963a

#### Search

```
`google_gcp_pubsub_message` data.protoPayload.authorizationInfo{}.resource=configmaps OR secrets  
| table data.protoPayload.requestMetadata.callerIp src_user data.resource.labels.cluster_name data.protoPayload.request.metadata.namespace data.labels.authorization.k8s.io/decision 
| dedup data.protoPayload.requestMetadata.callerIp src_user data.resource.labels.cluster_name 
|`kubernetes_gcp_detect_sensitive_object_access_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that `kubernetes_gcp_detect_sensitive_object_access_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk add on for GCP . This search works with pubsub messaging service logs.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_gcp_detect_sensitive_object_access.yml) \| *version*: **1**