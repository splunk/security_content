---
title: "Kubernetes Sensitive Object Access Activity"
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

This story addresses detection and response of accounts acccesing Kubernetes cluster sensitive objects such as configmaps or secrets providing information on items such as user user, group. object, namespace and authorization reason.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-05-20
- **Author**: Rod Soto, Splunk
- **ID**: c7d4dbf0-a171-4eaf-8444-4f40392e4f92

#### Narrative

Kubernetes is the most used container orchestration platform, this orchestration platform contains sensitive objects within its architecture, specifically configmaps and secrets, if accessed by an attacker can lead to further compromise. These searches allow operator to detect suspicious requests against Kubernetes sensitive objects.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS EKS Kubernetes cluster sensitive object access](/deprecated/aws_eks_kubernetes_cluster_sensitive_object_access/) | None| Hunting |
| [Kubernetes AWS detect service accounts forbidden failure access](/deprecated/kubernetes_aws_detect_service_accounts_forbidden_failure_access/) | None| Hunting |
| [Kubernetes Azure detect sensitive object access](/deprecated/kubernetes_azure_detect_sensitive_object_access/) | None| Hunting |
| [Kubernetes Azure detect service accounts forbidden failure access](/deprecated/kubernetes_azure_detect_service_accounts_forbidden_failure_access/) | None| Hunting |
| [Kubernetes Azure detect suspicious kubectl calls](/deprecated/kubernetes_azure_detect_suspicious_kubectl_calls/) | None| Hunting |
| [Kubernetes GCP detect sensitive object access](/deprecated/kubernetes_gcp_detect_sensitive_object_access/) | None| Hunting |
| [Kubernetes GCP detect service accounts forbidden failure access](/deprecated/kubernetes_gcp_detect_service_accounts_forbidden_failure_access/) | None| Hunting |
| [Kubernetes GCP detect suspicious kubectl calls](/deprecated/kubernetes_gcp_detect_suspicious_kubectl_calls/) | None| Hunting |
| [Kubernetes AWS detect suspicious kubectl calls](/cloud/kubernetes_aws_detect_suspicious_kubectl_calls/) | None| Hunting |

#### Reference

* [https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html](https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/kubernetes_sensitive_object_access_activity.yml) \| *version*: **1**