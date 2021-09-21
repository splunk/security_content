---
title: "Suspicious Cloud Provisioning Activities"
last_modified_at: 2018-08-20
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

- **ID**: 51045ded-1575-4ba6-aef7-af6c73cffd86
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2018-08-20
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Cloud Provisioning Activity From Previously Unseen City](/cloud/cloud_provisioning_activity_from_previously_unseen_city/) | None | Anomaly |
| [Cloud Provisioning Activity From Previously Unseen Country](/cloud/cloud_provisioning_activity_from_previously_unseen_country/) | None | Anomaly |
| [Cloud Provisioning Activity From Previously Unseen IP Address](/cloud/cloud_provisioning_activity_from_previously_unseen_ip_address/) | None | Anomaly |
| [Cloud Provisioning Activity From Previously Unseen Region](/cloud/cloud_provisioning_activity_from_previously_unseen_region/) | None | Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_cloud_provisioning_activities.yml) \| *version*: **1**