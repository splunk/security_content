---
title: "Kubernetes GCP detect service accounts forbidden failure access"
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

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-06-23
- **Author**: Rod Soto, Splunk
- **ID**: 7094808d-432a-48e7-bb3c-77e96c894f3b


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
`google_gcp_pubsub_message` system:serviceaccounts data.protoPayload.response.status.allowed!=* 
| table src_ip src_user http_user_agent data.protoPayload.response.spec.resourceAttributes.namespace data.resource.labels.cluster_name data.protoPayload.response.spec.resourceAttributes.verb  data.protoPayload.request.status.allowed data.protoPayload.response.status.reason data.labels.authorization.k8s.io/decision 
| dedup src_ip src_user 
| `kubernetes_gcp_detect_service_accounts_forbidden_failure_access_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that **kubernetes_gcp_detect_service_accounts_forbidden_failure_access_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk add on for GCP. This search works with pubsub messaging service logs.

#### Known False Positives
This search can give false positives as there might be inherent issues with authentications and permissions at cluster.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_gcp_detect_service_accounts_forbidden_failure_access.yml) \| *version*: **1**