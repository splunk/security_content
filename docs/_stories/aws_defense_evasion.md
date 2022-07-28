---
title: "AWS Defense Evasion"
last_modified_at: 2022-07-15
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Identify activity and techniques associated with the Evasion of Defenses within AWS, such as Disabling CloudTrail, Deleting CloudTrail and many others.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-07-15
- **Author**: Gowthamaraj Rajendran, Splunk
- **ID**: 4e00b690-293f-434d-a9d8-bcfb2ea5fff9

#### Narrative

Adversaries employ a variety of techniques in order to avoid detection and operate without barriers. This often involves modifying the configuration of security monitoring tools to get around them or explicitly disabling them to prevent them from running. This Analytic Story includes analytics that identify activity consistent with adversaries attempting to disable various security mechanisms on AWS. Such activity may involve deleting the CloudTrail logs , as this is where all the AWS logs get stored or explicitly changing the retention policy of S3 buckets. Other times, adversaries attempt deletion of a specified AWS CloudWatch log group.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Defense Evasion Delete Cloudtrail](/cloud/aws_defense_evasion_delete_cloudtrail/) | [Disable Cloud Logs](/tags/#disable-cloud-logs), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [AWS Defense Evasion Delete CloudWatch Log Group](/cloud/aws_defense_evasion_delete_cloudwatch_log_group/) | [Impair Defenses](/tags/#impair-defenses), [Disable Cloud Logs](/tags/#disable-cloud-logs)| TTP |
| [AWS Defense Evasion Impair Security Services](/cloud/aws_defense_evasion_impair_security_services/) | [Disable Cloud Logs](/tags/#disable-cloud-logs), [Impair Defenses](/tags/#impair-defenses)| Hunting |
| [AWS Defense Evasion PutBucketLifecycle](/cloud/aws_defense_evasion_putbucketlifecycle/) | [Disable Cloud Logs](/tags/#disable-cloud-logs), [Impair Defenses](/tags/#impair-defenses)| Hunting |
| [AWS Defense Evasion Stop Logging Cloudtrail](/cloud/aws_defense_evasion_stop_logging_cloudtrail/) | [Disable Cloud Logs](/tags/#disable-cloud-logs), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [AWS Defense Evasion Update Cloudtrail](/cloud/aws_defense_evasion_update_cloudtrail/) | [Impair Defenses](/tags/#impair-defenses), [Disable Cloud Logs](/tags/#disable-cloud-logs)| TTP |

#### Reference

* [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_defense_evasion.yml) \| *version*: **1**