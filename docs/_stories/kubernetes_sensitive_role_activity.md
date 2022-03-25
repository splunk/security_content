---
title: "Kubernetes Sensitive Role Activity"
last_modified_at: 2020-05-20
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story addresses detection and response around Sensitive Role usage within a Kubernetes clusters against cluster resources and namespaces.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-05-20
- **Author**: Rod Soto, Splunk
- **ID**: 8b3984d2-17b6-47e9-ba43-a3376e70fdcc

#### Narrative

Kubernetes is the most used container orchestration platform, this orchestration platform contains sensitive roles within its architecture, specifically configmaps and secrets, if accessed by an attacker can lead to further compromise. These searches allow operator to detect suspicious requests against Kubernetes role activities

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Kubernetes AWS detect most active service accounts by pod](/deprecated/kubernetes_aws_detect_most_active_service_accounts_by_pod/) | None| Hunting |
| [Kubernetes AWS detect RBAC authorization by account](/deprecated/kubernetes_aws_detect_rbac_authorization_by_account/) | None| Hunting |
| [Kubernetes AWS detect sensitive role access](/deprecated/kubernetes_aws_detect_sensitive_role_access/) | None| Hunting |
| [Kubernetes Azure active service accounts by pod namespace](/deprecated/kubernetes_azure_active_service_accounts_by_pod_namespace/) | None| Hunting |
| [Kubernetes Azure detect RBAC authorization by account](/deprecated/kubernetes_azure_detect_rbac_authorization_by_account/) | None| Hunting |
| [Kubernetes Azure detect sensitive role access](/deprecated/kubernetes_azure_detect_sensitive_role_access/) | None| Hunting |
| [Kubernetes GCP detect RBAC authorizations by account](/deprecated/kubernetes_gcp_detect_rbac_authorizations_by_account/) | None| Hunting |
| [Kubernetes GCP detect most active service accounts by pod](/deprecated/kubernetes_gcp_detect_most_active_service_accounts_by_pod/) | None| Hunting |
| [Kubernetes GCP detect sensitive role access](/deprecated/kubernetes_gcp_detect_sensitive_role_access/) | None| Hunting |

#### Reference

* [https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html](https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/kubernetes_sensitive_role_activity.yml) \| *version*: **1**