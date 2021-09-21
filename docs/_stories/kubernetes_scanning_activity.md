---
title: "Kubernetes Scanning Activity"
last_modified_at: 2020-04-15
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

This story addresses detection against Kubernetes cluster fingerprint scan and attack by providing information on items such as source ip, user agent, cluster names.

- **ID**: a9ef59cf-e981-4e66-9eef-bb049f695c09
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-04-15
- **Author**: Rod Soto, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Amazon EKS Kubernetes Pod scan detection](/cloud/amazon_eks_kubernetes_pod_scan_detection/) | None | Hunting |
| [Amazon EKS Kubernetes cluster scan detection](/cloud/amazon_eks_kubernetes_cluster_scan_detection/) | None | Hunting |
| [GCP Kubernetes cluster pod scan detection](/cloud/gcp_kubernetes_cluster_pod_scan_detection/) | None | Hunting |

#### Reference

* [https://github.com/splunk/cloud-datamodel-security-research](https://github.com/splunk/cloud-datamodel-security-research)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/kubernetes_scanning_activity.yml) | _version_: **1**