---
title: "Suspicious AWS Login Activities"
last_modified_at: 2019-05-01
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your AWS authentication events using your CloudTrail logs. Searches within this Analytic Story will help you stay aware of and investigate suspicious logins. 

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2019-05-01
- **Author**: Bhavin Patel, Splunk
- **ID**: 2e8948a5-5239-406b-b56b-6c59f1268af3

#### Narrative

It is important to monitor and control who has access to your AWS infrastructure. Detecting suspicious logins to your AWS infrastructure will provide good starting points for investigations. Abusive behaviors caused by compromised credentials can lead to direct monetary costs, as you will be billed for any EC2 instances created by the attacker.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect AWS Console Login by User from New City](/cloud/detect_aws_console_login_by_user_from_new_city/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Hunting |
| [Detect AWS Console Login by User from New Country](/cloud/detect_aws_console_login_by_user_from_new_country/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Hunting |
| [Detect AWS Console Login by User from New Region](/cloud/detect_aws_console_login_by_user_from_new_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Hunting |
| [Detect new user AWS Console Login](/deprecated/detect_new_user_aws_console_login/) | [Cloud Accounts](/tags/#cloud-accounts)| Hunting |

#### Reference

* [https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_aws_login_activities.yml) \| *version*: **1**