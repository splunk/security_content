---
title: "Suspicious Cloud Provisioning Activities"
last_modified_at: 2018-08-20
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
- **Last Updated**: 2018-08-20
- **Author**: David Dorsey, Splunk
- **ID**: 51045ded-1575-4ba6-aef7-af6c73cffd86

#### Narrative

Because most enterprise cloud infrastructure activities originate from familiar geographic locations, monitoring for activity from unknown or unusual regions is an important security measure. This indicator can be especially useful in environments where it is impossible to add specific IPs to an allow list because they vary.\
This Analytic Story was designed to provide you with flexibility in the precision you employ in specifying legitimate geographic regions. It can be as specific as an IP address or a city, or as broad as a region (think state) or an entire country. By determining how precise you want your geographical locations to be and monitoring for new locations that haven't previously accessed your environment, you can detect adversaries as they begin to probe your environment. Since there are legitimate reasons for activities from unfamiliar locations, this is not a standalone indicator. Nevertheless, location can be a relevant piece of information that you may wish to investigate further.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Cloud Provisioning Activity From Previously Unseen City](/cloud/cloud_provisioning_activity_from_previously_unseen_city/) | [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [Cloud Provisioning Activity From Previously Unseen Country](/cloud/cloud_provisioning_activity_from_previously_unseen_country/) | [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [Cloud Provisioning Activity From Previously Unseen IP Address](/cloud/cloud_provisioning_activity_from_previously_unseen_ip_address/) | [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [Cloud Provisioning Activity From Previously Unseen Region](/cloud/cloud_provisioning_activity_from_previously_unseen_region/) | [Valid Accounts](/tags/#valid-accounts)| Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_cloud_provisioning_activities.yml) \| *version*: **1**