---
title: "Container Implantation Monitoring and Investigation"
last_modified_at: 2020-02-20
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

Use the searches in this story to monitor your Kubernetes registry repositories for upload, and deployment of potentially vulnerable, backdoor, or implanted containers. These searches provide information on source users, destination path, container names and repository names. The searches provide context to address Mitre T1525 which refers to container implantation upload to a company's repository either in Amazon Elastic Container Registry, Google Container Registry and Azure Container Registry.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-02-20
- **Author**: Rod Soto, Rico Valdez, Splunk
- **ID**: aa0e28b1-0521-4b6f-9d2a-7b87e34af246

#### Narrative

Container Registrys provide a way for organizations to keep customized images of their development and infrastructure environment in private. However if these repositories are misconfigured or priviledge users credentials are compromise, attackers can potentially upload implanted containers which can be deployed across the organization. These searches allow operator to monitor who, when and what was uploaded to container registry.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [GCP GCR container uploaded](/deprecated/gcp_gcr_container_uploaded/) | [Implant Internal Image](/tags/#implant-internal-image)| Hunting |
| [New container uploaded to AWS ECR](/cloud/new_container_uploaded_to_aws_ecr/) | [Implant Internal Image](/tags/#implant-internal-image)| Hunting |

#### Reference

* [https://github.com/splunk/cloud-datamodel-security-research](https://github.com/splunk/cloud-datamodel-security-research)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/container_implantation_monitoring_and_investigation.yml) \| *version*: **1**