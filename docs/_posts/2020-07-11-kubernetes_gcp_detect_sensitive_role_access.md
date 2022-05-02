---
title: "Kubernetes GCP detect sensitive role access"
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

This search provides information on Kubernetes accounts accessing sensitve objects such as configmpas or secrets

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-11
- **Author**: Rod Soto, Splunk
- **ID**: a46923f6-36b9-4806-a681-31f314907c30


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
`google_gcp_pubsub_message` data.labels.authorization.k8s.io/reason=ClusterRoleBinding OR Clusterrole dest=apis/rbac.authorization.k8s.io/v1 src_ip!=::1  
| table src_ip src_user http_user_agent data.labels.authorization.k8s.io/decision data.labels.authorization.k8s.io/reason 
| dedup src_ip src_user 
|`kubernetes_gcp_detect_sensitive_role_access_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that **kubernetes_gcp_detect_sensitive_role_access_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk add on for GCP. This search works with pubsub messaging servicelogs.

#### Known False Positives
Sensitive role resource access is necessary for cluster operation, however source IP, user agent, decision and reason may indicate possible malicious use. 

#### Associated Analytic story
* [Kubernetes Sensitive Role Activity](/stories/kubernetes_sensitive_role_activity)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_gcp_detect_sensitive_role_access.yml) \| *version*: **1**