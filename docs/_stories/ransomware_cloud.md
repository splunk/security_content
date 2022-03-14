---
title: "Ransomware Cloud"
last_modified_at: 2020-10-27
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to ransomware. These searches include cloud related objects that may be targeted by malicious actors via cloud providers own encryption features.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-10-27
- **Author**: Rod Soto, David Dorsey, Splunk
- **ID**: f52f6c43-05f8-4b19-a9d3-5b8c56da91c2

#### Narrative

Ransomware is an ever-present risk to the enterprise, wherein an infected host encrypts business-critical data, holding it hostage until the victim pays the attacker a ransom. There are many types and varieties of ransomware that can affect an enterprise.Cloud ransomware can be deployed by obtaining high privilege credentials from targeted users or resources.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Detect Users creating keys with encrypt policy without MFA](/cloud/aws_detect_users_creating_keys_with_encrypt_policy_without_mfa/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact)| TTP |
| [AWS Detect Users with KMS keys performing encryption S3](/cloud/aws_detect_users_with_kms_keys_performing_encryption_s3/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact)| Anomaly |

#### Reference

* [https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/)
* [https://github.com/d1vious/git-wild-hunt](https://github.com/d1vious/git-wild-hunt)
* [https://www.youtube.com/watch?v=PgzNib37g0M](https://www.youtube.com/watch?v=PgzNib37g0M)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ransomware_cloud.yml) \| *version*: **1**