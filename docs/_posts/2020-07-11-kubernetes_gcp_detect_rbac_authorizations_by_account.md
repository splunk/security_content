---
title: "Kubernetes GCP detect RBAC authorizations by account"
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

This search provides information on Kubernetes RBAC authorizations by accounts, this search can be modified by adding top to see both extremes of RBAC by accounts occurrences

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-07-11
- **Author**: Rod Soto, Splunk
- **ID**: 99487de3-7192-4b41-939d-fbe9acfb1340

#### Search

```
`google_gcp_pubsub_message` data.labels.authorization.k8s.io/reason=ClusterRoleBinding OR Clusterrole  
| table src_ip src_user data.labels.authorization.k8s.io/decision data.labels.authorization.k8s.io/reason 
| rare src_user data.labels.authorization.k8s.io/reason 
|`kubernetes_gcp_detect_rbac_authorizations_by_account_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that `kubernetes_gcp_detect_rbac_authorizations_by_account_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk AWS add on for GCP. This search works with pubsub messaging service logs

#### Known False Positives
Not all RBAC Authorications are malicious. RBAC authorizations can uncover malicious activity specially if sensitive Roles have been granted.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_gcp_detect_rbac_authorizations_by_account.yml) \| *version*: **1**