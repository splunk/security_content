---
title: "Kubernetes Sensitive Object Access Activity"
last_modified_at: 2020-05-20
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

This story addresses detection and response of accounts acccesing Kubernetes cluster sensitive objects such as configmaps or secrets providing information on items such as user user, group. object, namespace and authorization reason.

- **ID**: 2574e6d9-7254-4751-8925-0447deeec8ea
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-05-20
- **Author**: Rod Soto, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Kubernetes AWS detect suspicious kubectl calls](/cloud/kubernetes_aws_detect_suspicious_kubectl_calls/) | None | Hunting |

#### Kill Chain Phase



#### Reference

* [https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html](https://www.splunk.com/en_us/blog/security/approaching-kubernetes-security-detecting-kubernetes-scan-with-splunk.html)



_version_: 1