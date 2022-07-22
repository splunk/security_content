---
title: "Cloud Cryptomining"
last_modified_at: 2019-10-02
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

Monitor your cloud compute instances for activities related to cryptojacking/cryptomining. New instances that originate from previously unseen regions, users who launch abnormally high numbers of instances, or compute instances started by previously unseen users are just a few examples of potentially malicious behavior.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2019-10-02
- **Author**: David Dorsey, Splunk
- **ID**: 3b96d13c-fdc7-45dd-b3ad-c132b31cdd2a

#### Narrative

Cryptomining is an intentionally difficult, resource-intensive business. Its complexity was designed into the process to ensure that the number of blocks mined each day would remain steady. So, it's par for the course that ambitious, but unscrupulous, miners make amassing the computing power of large enterprises--a practice known as cryptojacking--a top priority. \
Cryptojacking has attracted an increasing amount of media attention since its explosion in popularity in the fall of 2017. The attacks have moved from in-browser exploits and mobile phones to enterprise cloud services, such as Amazon Web Services (AWS), Google Cloud Platform (GCP), and Azure. It's difficult to determine exactly how widespread the practice has become, since bad actors continually evolve their ability to escape detection, including employing unlisted endpoints, moderating their CPU usage, and hiding the mining pool's IP address behind a free CDN. \
When malicious miners appropriate a cloud instance, often spinning up hundreds of new instances, the costs can become astronomical for the account holder. So it is critically important to monitor your systems for suspicious activities that could indicate that your network has been infiltrated. \
This Analytic Story is focused on detecting suspicious new instances in your cloud environment to help prevent cryptominers from gaining a foothold. It contains detection searches that will detect when a previously unused instance type or AMI is used. It also contains support searches to build lookup files to ensure proper execution of the detection searches.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Cloud Compute Instance Created By Previously Unseen User](/cloud/cloud_compute_instance_created_by_previously_unseen_user/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [Cloud Compute Instance Created In Previously Unused Region](/cloud/cloud_compute_instance_created_in_previously_unused_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Anomaly |
| [Cloud Compute Instance Created With Previously Unseen Image](/cloud/cloud_compute_instance_created_with_previously_unseen_image/) | None| Anomaly |
| [Cloud Compute Instance Created With Previously Unseen Instance Type](/cloud/cloud_compute_instance_created_with_previously_unseen_instance_type/) | None| Anomaly |
| [Abnormally High Number Of Cloud Instances Launched](/cloud/abnormally_high_number_of_cloud_instances_launched/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts)| Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cloud_cryptomining.yml) \| *version*: **1**