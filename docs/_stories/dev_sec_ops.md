---
title: "Dev Sec Ops"
last_modified_at: 2021-08-18
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story is focused around detecting attacks on a DevSecOps lifeccycle which consists of the phases plan, code, build, test, release, deploy, operate and monitor.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-08-18
- **Author**: Patrick Bareiss, Splunk
- **ID**: 0ca8c38e-631e-4b81-940c-f9c5450ce41e

#### Narrative

DevSecOps is a collaborative framework, which thinks about application and infrastructure security from the start. This means that security tools are part of the continuous integration and continuous deployment pipeline. In this analytics story, we focused on detections around the tools used in this framework such as GitHub as a version control system, GDrive for the documentation, CircleCI as the CI/CD pipeline, Kubernetes as the container execution engine and multiple security tools such as Semgrep and Kube-Hunter.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS ECR Container Scanning Findings High](/cloud/aws_ecr_container_scanning_findings_high/) | None| TTP |
| [AWS ECR Container Scanning Findings Low Informational Unknown](/cloud/aws_ecr_container_scanning_findings_low_informational_unknown/) | None| Hunting |
| [AWS ECR Container Scanning Findings Medium](/cloud/aws_ecr_container_scanning_findings_medium/) | None| Anomaly |
| [AWS ECR Container Upload Outside Business Hours](/cloud/aws_ecr_container_upload_outside_business_hours/) | None| Anomaly |
| [AWS ECR Container Upload Unknown User](/cloud/aws_ecr_container_upload_unknown_user/) | None| Anomaly |
| [Circle CI Disable Security Job](/cloud/circle_ci_disable_security_job/) | None| Anomaly |
| [Circle CI Disable Security Step](/cloud/circle_ci_disable_security_step/) | None| Anomaly |
| [Correlation by Repository and Risk](/cloud/correlation_by_repository_and_risk/) | None| Correlation |
| [Correlation by User and Risk](/cloud/correlation_by_user_and_risk/) | None| Correlation |
| [Github Commit Changes In Master](/cloud/github_commit_changes_in_master/) | None| Anomaly |
| [Github Commit In Develop](/cloud/github_commit_in_develop/) | None| Anomaly |
| [GitHub Dependabot Alert](/cloud/github_dependabot_alert/) | None| Anomaly |
| [GitHub Pull Request from Unknown User](/cloud/github_pull_request_from_unknown_user/) | None| Anomaly |
| [Gsuite Drive Share In External Email](/cloud/gsuite_drive_share_in_external_email/) | None| Anomaly |
| [GSuite Email Suspicious Attachment](/cloud/gsuite_email_suspicious_attachment/) | None| Anomaly |
| [Gsuite Email Suspicious Subject With Attachment](/cloud/gsuite_email_suspicious_subject_with_attachment/) | None| Anomaly |
| [Gsuite Email With Known Abuse Web Service Link](/cloud/gsuite_email_with_known_abuse_web_service_link/) | None| Anomaly |
| [Gsuite Outbound Email With Attachment To External Domain](/cloud/gsuite_outbound_email_with_attachment_to_external_domain/) | None| Anomaly |
| [Gsuite Suspicious Shared File Name](/cloud/gsuite_suspicious_shared_file_name/) | None| Anomaly |
| [Kubernetes Nginx Ingress LFI](/cloud/kubernetes_nginx_ingress_lfi/) | None| TTP |
| [Kubernetes Nginx Ingress RFI](/cloud/kubernetes_nginx_ingress_rfi/) | None| TTP |
| [Kubernetes Scanner Image Pulling](/cloud/kubernetes_scanner_image_pulling/) | None| TTP |

#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dev_sec_ops.yml) \| *version*: **1**