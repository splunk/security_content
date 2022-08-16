---
title: "AWS Credential Access"
last_modified_at: 2022-08-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Identify activity and techniques associated with accessing credential files from AWS resources, monitor unusual authentication related activities to the AWS Console and other services such as RDS.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2022-08-19
- **Author**: Gowthamaraj Rajendran, Bhavin Patel,  Splunk
- **ID**: 4210b690-293f-411d-a9d8-bcfb2ea5fff9

#### Narrative

Adversaries employ a variety of techniques to steal AWS Cloud credentials like account names, passwords and keys. Usage of legitimate keys will assist the attackers to gain access to other sensitive system and they can also mimic legitimate behaviour making them harder to be detected. Such activity may involve mulitple failed login to the console, new console logins and password reset activities.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Credential Access Failed Login](/cloud/aws_credential_access_failed_login/) | [Password Guessing](/tags/#password-guessing)| TTP |
| [AWS Credential Access GetPasswordData](/cloud/aws_credential_access_getpassworddata/) | [Unsecured Credentials](/tags/#unsecured-credentials)| Anomaly |
| [AWS Credential Access RDS Password reset](/cloud/aws_credential_access_rds_password_reset/) | [Password Cracking](/tags/#password-cracking)| TTP |
| [Detect AWS Console Login by New User](/cloud/detect_aws_console_login_by_new_user/) | None| Hunting |
| [Detect AWS Console Login by User from New City](/cloud/detect_aws_console_login_by_user_from_new_city/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Hunting |
| [Detect AWS Console Login by User from New Country](/cloud/detect_aws_console_login_by_user_from_new_country/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Hunting |
| [Detect AWS Console Login by User from New Region](/cloud/detect_aws_console_login_by_user_from_new_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Hunting |

#### Reference

* [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_credential_access.yml) \| *version*: **1**