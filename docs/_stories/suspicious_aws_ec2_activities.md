---
title: "Suspicious AWS EC2 Activities"
last_modified_at: 2018-02-09
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

Use the searches in this Analytic Story to monitor your AWS EC2 instances for evidence of anomalous activity and suspicious behaviors, such as EC2 instances that originate from unusual locations or those launched by previously unseen users (among others). Included investigative searches will help you probe more deeply, when the information warrants it.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-02-09
- **Author**: Bhavin Patel, Splunk
- **ID**: 2e8948a5-5239-406b-b56b-6c50f1268af3

#### Narrative

AWS CloudTrail is an AWS service that helps you enable governance, compliance, and risk auditing within your AWS account. Actions taken by a user, role, or an AWS service are recorded as events in CloudTrail. It is crucial for a company to monitor events and actions taken in the AWS Console, AWS command-line interface, and AWS SDKs and APIs to ensure that your EC2 instances are not vulnerable to attacks. This Analytic Story identifies suspicious activities in your AWS EC2 instances and helps you respond and investigate those activities.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Abnormally High AWS Instances Launched by User](/deprecated/abnormally_high_aws_instances_launched_by_user/) | [Cloud Accounts](/tags/#cloud-accounts)| Anomaly |
| [Abnormally High AWS Instances Launched by User - MLTK](/deprecated/abnormally_high_aws_instances_launched_by_user_-_mltk/) | [Cloud Accounts](/tags/#cloud-accounts)| Anomaly |
| [Abnormally High AWS Instances Terminated by User](/deprecated/abnormally_high_aws_instances_terminated_by_user/) | [Cloud Accounts](/tags/#cloud-accounts)| Anomaly |
| [Abnormally High AWS Instances Terminated by User - MLTK](/deprecated/abnormally_high_aws_instances_terminated_by_user_-_mltk/) | [Cloud Accounts](/tags/#cloud-accounts)| Anomaly |
| [EC2 Instance Started In Previously Unseen Region](/deprecated/ec2_instance_started_in_previously_unseen_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Anomaly |
| [EC2 Instance Started With Previously Unseen User](/deprecated/ec2_instance_started_with_previously_unseen_user/) | [Cloud Accounts](/tags/#cloud-accounts)| Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_aws_ec2_activities.yml) \| *version*: **1**