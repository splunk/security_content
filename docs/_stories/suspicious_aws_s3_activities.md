---
title: "Suspicious AWS S3 Activities"
last_modified_at: 2018-07-24
toc: true
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Use the searches in this Analytic Story to monitor your AWS S3 buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open S3 buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

- **ID**: 2e8948a5-5239-406b-b56b-6c50w3168af3
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-07-24
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect New Open S3 Buckets over AWS CLI](/cloud/detect_new_open_s3_buckets_over_aws_cli/) | None | TTP |
| [Detect New Open S3 buckets](/cloud/detect_new_open_s3_buckets/) | None | TTP |
| [Detect S3 access from a new IP](/cloud/detect_s3_access_from_a_new_ip/) | None | Anomaly |
| [Detect Spike in S3 Bucket deletion](/cloud/detect_spike_in_s3_bucket_deletion/) | None | Anomaly |

#### Kill Chain Phase



#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)
* [https://www.tripwire.com/state-of-security/security-data-protection/cloud/public-aws-s3-buckets-writable/](https://www.tripwire.com/state-of-security/security-data-protection/cloud/public-aws-s3-buckets-writable/)



_version_: 2