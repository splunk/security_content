---
title: "AWS Suspicious Provisioning Activities"
last_modified_at: 2018-03-16
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

Monitor your AWS provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your network.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-03-16
- **Author**: David Dorsey, Splunk
- **ID**: 3338b567-3804-4261-9889-cf0ca4753c7f

#### Narrative

Because most enterprise AWS activities originate from familiar geographic locations, monitoring for activity from unknown or unusual regions is an important security measure. This indicator can be especially useful in environments where it is impossible to add specific IPs to an allow list because they vary. \
This Analytic Story was designed to provide you with flexibility in the precision you employ in specifying legitimate geographic regions. It can be as specific as an IP address or a city, or as broad as a region (think state) or an entire country. By determining how precise you want your geographical locations to be and monitoring for new locations that haven't previously accessed your environment, you can detect adversaries as they begin to probe your environment. Since there are legitimate reasons for activities from unfamiliar locations, this is not a standalone indicator. Nevertheless, location can be a relevant piece of information that you may wish to investigate further.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Cloud Provisioning From Previously Unseen City](/deprecated/aws_cloud_provisioning_from_previously_unseen_city/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Anomaly |
| [AWS Cloud Provisioning From Previously Unseen Country](/deprecated/aws_cloud_provisioning_from_previously_unseen_country/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Anomaly |
| [AWS Cloud Provisioning From Previously Unseen IP Address](/deprecated/aws_cloud_provisioning_from_previously_unseen_ip_address/) | None| Anomaly |
| [AWS Cloud Provisioning From Previously Unseen Region](/deprecated/aws_cloud_provisioning_from_previously_unseen_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_suspicious_provisioning_activities.yml) \| *version*: **1**