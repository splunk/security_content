---
title: "AWS Security Hub Alerts"
last_modified_at: 2020-08-04
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This story is focused around detecting Security Hub alerts generated from AWS

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-08-04
- **Author**: Bhavin Patel, Splunk
- **ID**: 2f2f610a-d64d-48c2-b57c-96722b49ab5a

#### Narrative

AWS Security Hub collects and consolidates findings from AWS security services enabled in your environment, such as intrusion detection findings from Amazon GuardDuty, vulnerability scans from Amazon Inspector, S3 bucket policy findings from Amazon Macie, publicly accessible and cross-account resources from IAM Access Analyzer, and resources lacking WAF coverage from AWS Firewall Manager.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Spike in AWS Security Hub Alerts for EC2 Instance](/cloud/detect_spike_in_aws_security_hub_alerts_for_ec2_instance/) | None| Anomaly |
| [Detect Spike in AWS Security Hub Alerts for User](/cloud/detect_spike_in_aws_security_hub_alerts_for_user/) | None| Anomaly |

#### Reference

* [https://aws.amazon.com/security-hub/features/](https://aws.amazon.com/security-hub/features/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_security_hub_alerts.yml) \| *version*: **1**