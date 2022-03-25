---
title: "Kubernetes GCP detect most active service accounts by pod"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2020-07-10
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


- **Last Updated**: 2020-07-10
- **Author**: Rod Soto, Splunk
- **ID**: 7f5c2779-88a0-4824-9caa-0f606c8f260f

#### Search

```
`google_gcp_pubsub_message`  data.protoPayload.request.spec.group{}=system:serviceaccounts 
| table src_ip src_user http_user_agent data.protoPayload.request.spec.nonResourceAttributes.verb data.labels.authorization.k8s.io/decision data.protoPayload.response.spec.resourceAttributes.resource 
| top src_ip src_user http_user_agent data.labels.authorization.k8s.io/decision data.protoPayload.response.spec.resourceAttributes.resource 
|`kubernetes_gcp_detect_most_active_service_accounts_by_pod_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that `kubernetes_gcp_detect_most_active_service_accounts_by_pod_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk GCP add on. This search works with pubsub messaging service logs

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_gcp_detect_most_active_service_accounts_by_pod.yml) \| *version*: **1**