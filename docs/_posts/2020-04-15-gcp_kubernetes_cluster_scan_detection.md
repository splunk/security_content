---
title: "GCP Kubernetes cluster scan detection"
excerpt: "Cloud Service Discovery
"
categories:
  - Deprecated
last_modified_at: 2020-04-15
toc: true
toc_label: ""
tags:
  - Cloud Service Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information of unauthenticated requests via user agent, and authentication data against Kubernetes cluster

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-04-15
- **Author**: Rod Soto, Splunk
- **ID**: db5957ec-0144-4c56-b512-9dccbe7a2d26


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1526](https://attack.mitre.org/techniques/T1526/) | Cloud Service Discovery | Discovery |

#### Search

```
`google_gcp_pubsub_message` data.protoPayload.requestMetadata.callerIp!=127.0.0.1 data.protoPayload.requestMetadata.callerIp!=::1 "data.labels.authorization.k8s.io/decision"=forbid "data.protoPayload.status.message"=PERMISSION_DENIED data.protoPayload.authenticationInfo.principalEmail="system:anonymous" 
| rename data.protoPayload.requestMetadata.callerIp as src_ip 
| stats count min(_time) as firstTime max(_time) as lastTime values(data.protoPayload.methodName) as method_name values(data.protoPayload.resourceName) as resource_name values(data.protoPayload.requestMetadata.callerSuppliedUserAgent) as http_user_agent by src_ip data.resource.labels.cluster_name 
| rename data.resource.labels.cluster_name as cluster_name
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)`  
| `gcp_kubernetes_cluster_scan_detection_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `gcp_kubernetes_cluster_scan_detection_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install the GCP App for Splunk (version 2.0.0 or later), then configure stackdriver and set a Pub/Sub subscription to be imported to Splunk. You must also install Cloud Infrastructure data model.Customize the macro kubernetes_gcp_scan_fingerprint_attack_detection to filter out FPs.

#### Known False Positives
Not all unauthenticated requests are malicious, but frequency, User Agent and source IPs will provide context.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/gcp_kubernetes_cluster_scan_detection.yml) \| *version*: **1**