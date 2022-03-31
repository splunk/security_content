---
title: "Kubernetes GCP detect suspicious kubectl calls"
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

This search provides information on anonymous Kubectl calls with IP, verb namespace and object access context

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-11
- **Author**: Rod Soto, Splunk
- **ID**: a5bed417-070a-41f2-a1e4-82b6aa281557


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`google_gcp_pubsub_message` data.protoPayload.requestMetadata.callerSuppliedUserAgent=kubectl* src_user=system:unsecured OR src_user=system:anonymous 
| table src_ip src_user data.protoPayload.requestMetadata.callerSuppliedUserAgent data.protoPayload.authorizationInfo{}.granted object_path 
|dedup src_ip src_user 
|`kubernetes_gcp_detect_suspicious_kubectl_calls_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that **kubernetes_gcp_detect_suspicious_kubectl_calls_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk add on for GCP. This search works with pubsub messaging logs.

#### Known False Positives
Kubectl calls are not malicious by nature. However source IP, source user, user agent, object path, and authorization context can reveal potential malicious activity, specially anonymous suspicious IPs and sensitive objects such as configmaps or secrets

#### Associated Analytic story
* [Kubernetes Sensitive Object Access Activity](/stories/kubernetes_sensitive_object_access_activity)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_gcp_detect_suspicious_kubectl_calls.yml) \| *version*: **1**