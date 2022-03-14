---
title: "AWS Cryptomining"
last_modified_at: 2018-03-08
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

Monitor your AWS EC2 instances for activities related to cryptojacking/cryptomining. New instances that originate from previously unseen regions, users who launch abnormally high numbers of instances, or EC2 instances started by previously unseen users are just a few examples of potentially malicious behavior.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-03-08
- **Author**: David Dorsey, Splunk
- **ID**: ced74200-8465-4bc3-bd2c-9a782eec6750

#### Narrative

Cryptomining is an intentionally difficult, resource-intensive business. Its complexity was designed into the process to ensure that the number of blocks mined each day would remain steady. So, it's par for the course that ambitious, but unscrupulous, miners make amassing the computing power of large enterprises--a practice known as cryptojacking--a top priority. \
Cryptojacking has attracted an increasing amount of media attention since its explosion in popularity in the fall of 2017. The attacks have moved from in-browser exploits and mobile phones to enterprise cloud services, such as Amazon Web Services (AWS). It's difficult to determine exactly how widespread the practice has become, since bad actors continually evolve their ability to escape detection, including employing unlisted endpoints, moderating their CPU usage, and hiding the mining pool's IP address behind a free CDN. \
When malicious miners appropriate a cloud instance, often spinning up hundreds of new instances, the costs can become astronomical for the account holder. So, it is critically important to monitor your systems for suspicious activities that could indicate that your network has been infiltrated. \
This Analytic Story is focused on detecting suspicious new instances in your EC2 environment to help prevent such a disaster. It contains detection searches that will detect when a previously unused instance type or AMI is used. It also contains support searches to build lookup files to ensure proper execution of the detection searches.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Abnormally High AWS Instances Launched by User](/deprecated/abnormally_high_aws_instances_launched_by_user/) | [Cloud Accounts](/tags/#cloud-accounts)| Anomaly |
| [Abnormally High AWS Instances Launched by User - MLTK](/deprecated/abnormally_high_aws_instances_launched_by_user_-_mltk/) | [Cloud Accounts](/tags/#cloud-accounts)| Anomaly |
| [EC2 Instance Started In Previously Unseen Region](/deprecated/ec2_instance_started_in_previously_unseen_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Anomaly |
| [EC2 Instance Started With Previously Unseen AMI](/deprecated/ec2_instance_started_with_previously_unseen_ami/) | None| Anomaly |
| [EC2 Instance Started With Previously Unseen Instance Type](/deprecated/ec2_instance_started_with_previously_unseen_instance_type/) | None| Anomaly |
| [EC2 Instance Started With Previously Unseen User](/deprecated/ec2_instance_started_with_previously_unseen_user/) | [Cloud Accounts](/tags/#cloud-accounts)| Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_cryptomining.yml) \| *version*: **1**