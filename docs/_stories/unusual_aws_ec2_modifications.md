---
title: "Unusual AWS EC2 Modifications"
last_modified_at: 2018-04-09
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

Identify unusual changes to your AWS EC2 instances that may indicate malicious activity. Modifications to your EC2 instances by previously unseen users is an example of an activity that may warrant further investigation.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-04-09
- **Author**: David Dorsey, Splunk
- **ID**: 73de57ef-0dfc-411f-b1e7-fa24428aeae0

#### Narrative

A common attack technique is to infiltrate a cloud instance and make modifications. The adversary can then secure access to your infrastructure or hide their activities. So it's important to stay alert to changes that may indicate that your environment has been compromised. \
 Searches within this Analytic Story can help you detect the presence of a threat by monitoring for EC2 instances that have been created or changed--either by users that have never previously performed these activities or by known users who modify or create instances in a way that have not been done before. This story also provides investigative searches that help you go deeper once you detect suspicious behavior.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [EC2 Instance Modified With Previously Unseen User](/deprecated/ec2_instance_modified_with_previously_unseen_user/) | [Cloud Accounts](/tags/#cloud-accounts)| Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/unusual_aws_ec2_modifications.yml) \| *version*: **1**