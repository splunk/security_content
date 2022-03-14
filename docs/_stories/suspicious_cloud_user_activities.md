---
title: "Suspicious Cloud User Activities"
last_modified_at: 2020-09-04
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
  - Actions on Objectives
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate suspicious activities by users and roles in your cloud environments.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-09-04
- **Author**: David Dorsey, Splunk
- **ID**: 1ed5ce7d-5469-4232-92af-89d1a3595b39

#### Narrative

It seems obvious that it is critical to monitor and control the users who have access to your cloud infrastructure. Nevertheless, it's all too common for enterprises to lose track of ad-hoc accounts, leaving their servers vulnerable to attack. In fact, this was the very oversight that led to Tesla's cryptojacking attack in February, 2018.\
In addition to compromising the security of your data, when bad actors leverage your compute resources, it can incur monumental costs, since you will be billed for any new instances and increased bandwidth usage.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Abnormally High Number Of Cloud Infrastructure API Calls](/cloud/abnormally_high_number_of_cloud_infrastructure_api_calls/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [Abnormally High Number Of Cloud Security Group API Calls](/cloud/abnormally_high_number_of_cloud_security_group_api_calls/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [AWS IAM AccessDenied Discovery Events](/cloud/aws_iam_accessdenied_discovery_events/) | [Cloud Infrastructure Discovery](/tags/#cloud-infrastructure-discovery)| Anomaly |
| [AWS Lambda UpdateFunctionCode](/cloud/aws_lambda_updatefunctioncode/) | [User Execution](/tags/#user-execution)| Hunting |
| [Cloud API Calls From Previously Unseen User Roles](/cloud/cloud_api_calls_from_previously_unseen_user_roles/) | [Valid Accounts](/tags/#valid-accounts)| Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)
* [https://redlock.io/blog/cryptojacking-tesla](https://redlock.io/blog/cryptojacking-tesla)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_cloud_user_activities.yml) \| *version*: **1**