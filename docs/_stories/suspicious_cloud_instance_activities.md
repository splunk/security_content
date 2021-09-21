---
title: "Suspicious Cloud Instance Activities"
last_modified_at: 2020-08-25
toc: true
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
---

#### Description

Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

- **ID**: 8168ca88-392e-42f4-85a2-767579c660ce
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-08-25
- **Author**: David Dorsey, Splunk

#### Narrative

Monitoring your cloud infrastructure logs allows you enable governance, compliance, and risk auditing. It is crucial for a company to monitor events and actions taken in the their cloud environments to ensure that your instances are not vulnerable to attacks. This Analytic Story identifies suspicious activities in your cloud compute instances and helps you respond and investigate those activities.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Abnormally High Number Of Cloud Instances Destroyed](/cloud/abnormally_high_number_of_cloud_instances_destroyed/) | None | Anomaly |
| [Abnormally High Number Of Cloud Instances Launched](/cloud/abnormally_high_number_of_cloud_instances_launched/) | None | Anomaly |
| [Cloud Instance Modified By Previously Unseen User](/cloud/cloud_instance_modified_by_previously_unseen_user/) | None | Anomaly |
| [Detect shared ec2 snapshot](/cloud/detect_shared_ec2_snapshot/) | None | TTP |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_cloud_instance_activities.yml) \| *version*: **1**