---
title: "Kubernetes Scanning Activity"
last_modified_at: 2020-04-15
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story addresses detection against Kubernetes cluster fingerprint scan and attack by providing information on items such as source ip, user agent, cluster names.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-04-15
- **Author**: Rod Soto, Splunk
- **ID**: a9ef59cf-e981-4e66-9eef-bb049f695c09

#### Narrative

Kubernetes is the most used container orchestration platform, this orchestration platform contains sensitve information and management priviledges of production workloads, microservices and applications. These searches allow operator to detect suspicious unauthenticated requests from the internet to kubernetes cluster.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [GCP Kubernetes cluster scan detection](/deprecated/gcp_kubernetes_cluster_scan_detection/) | [Cloud Service Discovery](/tags/#cloud-service-discovery)| TTP |
| [Kubernetes Azure pod scan fingerprint](/deprecated/kubernetes_azure_pod_scan_fingerprint/) | None| Hunting |
| [Kubernetes Azure scan fingerprint](/deprecated/kubernetes_azure_scan_fingerprint/) | [Cloud Service Discovery](/tags/#cloud-service-discovery)| Hunting |
| [Amazon EKS Kubernetes cluster scan detection](/cloud/amazon_eks_kubernetes_cluster_scan_detection/) | [Cloud Service Discovery](/tags/#cloud-service-discovery)| Hunting |
| [Amazon EKS Kubernetes Pod scan detection](/cloud/amazon_eks_kubernetes_pod_scan_detection/) | [Cloud Service Discovery](/tags/#cloud-service-discovery)| Hunting |
| [GCP Kubernetes cluster pod scan detection](/cloud/gcp_kubernetes_cluster_pod_scan_detection/) | [Cloud Service Discovery](/tags/#cloud-service-discovery)| Hunting |

#### Reference

* [https://github.com/splunk/cloud-datamodel-security-research](https://github.com/splunk/cloud-datamodel-security-research)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/kubernetes_scanning_activity.yml) \| *version*: **1**