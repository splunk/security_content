---
title: "Kubernetes AWS detect RBAC authorization by account"
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

This search provides information on Kubernetes RBAC authorizations by accounts, this search can be modified by adding top to see both extremes of RBAC by accounts occurrences

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-06-23
- **Author**: Rod Soto, Splunk
- **ID**: de7264ed-3ed9-4fef-bb01-6eefc87cefe8


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
`aws_cloudwatchlogs_eks` annotations.authorization.k8s.io/reason=* 
| table sourceIPs{} user.username userAgent annotations.authorization.k8s.io/reason 
| stats count by user.username annotations.authorization.k8s.io/reason 
| rare user.username annotations.authorization.k8s.io/reason 
|`kubernetes_aws_detect_rbac_authorization_by_account_filter`
```

#### Macros
The SPL above uses the following Macros:
* [aws_cloudwatchlogs_eks](https://github.com/splunk/security_content/blob/develop/macros/aws_cloudwatchlogs_eks.yml)

Note that **kubernetes_aws_detect_rbac_authorization_by_account_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with cloudwatch logs

#### Known False Positives
Not all RBAC Authorications are malicious. RBAC authorizations can uncover malicious activity specially if sensitive Roles have been granted.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/kubernetes_aws_detect_rbac_authorization_by_account.yml) \| *version*: **1**