---
title: "Dev Sec Ops"
last_modified_at: 2021-08-18
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story is focused around detecting attacks on a DevSecOps lifeccycle which consists of the phases plan, code, build, test, release, deploy, operate and monitor.

- **ID**: 0ca8c38e-631e-4b81-940c-f9c5450ce41e
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-08-18
- **Author**: Patrick Bareiss, Splunk

#### Narrative

DevSecOps is a collaborative framework, which thinks about application and infrastructure security from the start. This means that security tools are part of the continuous integration and continuous deployment pipeline. In this analytics story, we focused on detections around the tools used in this framework such as GitHub as a version control system, GDrive for the documentation, CircleCI as the CI/CD pipeline, Kubernetes as the container execution engine and multiple security tools such as Semgrep and Kube-Hunter.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS ECR Container Scanning Findings High](/cloud/aws_ecr_container_scanning_findings_high/) | [Malicious Image](/tags/#malicious-image), [Compromise Client Software Binary](/tags/#compromise-client-software-binary), [Compromise Software Dependencies and Development Tools](/tags/#compromise-software-dependencies-and-development-tools), [Exploitation for Credential Access](/tags/#exploitation-for-credential-access), [Cloud Service Discovery](/tags/#cloud-service-discovery) | TTP |
| [AWS ECR Container Scanning Findings Low Informational Unknown](/cloud/aws_ecr_container_scanning_findings_low_informational_unknown/) | [Malicious Image](/tags/#malicious-image) | Hunting |
| [AWS ECR Container Scanning Findings Medium](/cloud/aws_ecr_container_scanning_findings_medium/) | [Malicious Image](/tags/#malicious-image) | Anomaly |
| [AWS ECR Container Upload Outside Business Hours](/cloud/aws_ecr_container_upload_outside_business_hours/) | [Malicious Image](/tags/#malicious-image) | Anomaly |
| [AWS ECR Container Upload Unknown User](/cloud/aws_ecr_container_upload_unknown_user/) | [Malicious Image](/tags/#malicious-image) | Anomaly |
| [Circle CI Disable Security Job](/cloud/circle_ci_disable_security_job/) | [Compromise Client Software Binary](/tags/#compromise-client-software-binary) | Anomaly |
| [Circle CI Disable Security Step](/cloud/circle_ci_disable_security_step/) | [Compromise Client Software Binary](/tags/#compromise-client-software-binary) | Anomaly |
| [GitHub Dependabot Alert](/cloud/github_dependabot_alert/) | [Compromise Software Dependencies and Development Tools](/tags/#compromise-software-dependencies-and-development-tools) | Anomaly |
| [GitHub Pull Request from Unknown User](/cloud/github_pull_request_from_unknown_user/) | [Compromise Software Dependencies and Development Tools](/tags/#compromise-software-dependencies-and-development-tools) | Anomaly |
| [Kubernetes Nginx Ingress LFI](/cloud/kubernetes_nginx_ingress_lfi/) | [Exploitation for Credential Access](/tags/#exploitation-for-credential-access) | TTP |
| [Kubernetes Nginx Ingress RFI](/cloud/kubernetes_nginx_ingress_rfi/) | [Exploitation for Credential Access](/tags/#exploitation-for-credential-access) | TTP |
| [Kubernetes Scanner Image Pulling](/cloud/kubernetes_scanner_image_pulling/) | [Cloud Service Discovery](/tags/#cloud-service-discovery) | TTP |

#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dev_sec_ops.yml) \| *version*: **1**