---
title: "Suspicious Cloud User Activities"
last_modified_at: 2020-09-04
toc: true
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
---

#### Description

Detect and investigate suspicious activities by users and roles in your cloud environments.

- **ID**: 1ed5ce7d-5469-4232-92af-89d1a3595b39
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-09-04
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS IAM AccessDenied Discovery Events](/cloud/aws_iam_accessdenied_discovery_events/) | None | Anomaly |
| [Abnormally High Number Of Cloud Infrastructure API Calls](/cloud/abnormally_high_number_of_cloud_infrastructure_api_calls/) | None | Anomaly |
| [Abnormally High Number Of Cloud Security Group API Calls](/cloud/abnormally_high_number_of_cloud_security_group_api_calls/) | None | Anomaly |
| [Cloud API Calls From Previously Unseen User Roles](/cloud/cloud_api_calls_from_previously_unseen_user_roles/) | None | Anomaly |

#### Kill Chain Phase



#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)
* [https://redlock.io/blog/cryptojacking-tesla](https://redlock.io/blog/cryptojacking-tesla)



_version_: 1