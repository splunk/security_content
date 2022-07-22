---
title: "Suspicious Cloud Instance Activities"
last_modified_at: 2020-08-25
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-08-25
- **Author**: David Dorsey, Splunk
- **ID**: 8168ca88-392e-42f4-85a2-767579c660ce

#### Narrative

Monitoring your cloud infrastructure logs allows you enable governance, compliance, and risk auditing. It is crucial for a company to monitor events and actions taken in the their cloud environments to ensure that your instances are not vulnerable to attacks. This Analytic Story identifies suspicious activities in your cloud compute instances and helps you respond and investigate those activities.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Cloud Instance Modified By Previously Unseen User](/cloud/cloud_instance_modified_by_previously_unseen_user/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [Detect shared ec2 snapshot](/cloud/detect_shared_ec2_snapshot/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account)| TTP |
| [Abnormally High Number Of Cloud Instances Destroyed](/cloud/abnormally_high_number_of_cloud_instances_destroyed/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [Abnormally High Number Of Cloud Instances Launched](/cloud/abnormally_high_number_of_cloud_instances_launched/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts)| Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_cloud_instance_activities.yml) \| *version*: **1**