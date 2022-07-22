---
title: "Suspicious AWS S3 Activities"
last_modified_at: 2018-07-24
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Use the searches in this Analytic Story to monitor your AWS S3 buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open S3 buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-07-24
- **Author**: Bhavin Patel, Splunk
- **ID**: 66732346-8fb0-407b-9633-da16756567d6

#### Narrative

As cloud computing has exploded, so has the number of creative attacks on virtual environments. And as the number-two cloud-service provider, Amazon Web Services (AWS) has certainly had its share.\
Amazon's "shared responsibility" model dictates that the company has responsibility for the environment outside of the VM and the customer is responsible for the security inside of the S3 container. As such, it's important to stay vigilant for activities that may belie suspicious behavior inside of your environment.\
Among things to look out for are S3 access from unfamiliar locations and by unfamiliar users. Some of the searches in this Analytic Story help you detect suspicious behavior and others help you investigate more deeply, when the situation warrants.   

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect New Open S3 buckets](/cloud/detect_new_open_s3_buckets/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object)| TTP |
| [Detect New Open S3 Buckets over AWS CLI](/cloud/detect_new_open_s3_buckets_over_aws_cli/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object)| TTP |
| [Detect S3 access from a new IP](/cloud/detect_s3_access_from_a_new_ip/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object)| Anomaly |
| [Detect Spike in S3 Bucket deletion](/cloud/detect_spike_in_s3_bucket_deletion/) | [Data from Cloud Storage Object](/tags/#data-from-cloud-storage-object)| Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)
* [https://www.tripwire.com/state-of-security/security-data-protection/cloud/public-aws-s3-buckets-writable/](https://www.tripwire.com/state-of-security/security-data-protection/cloud/public-aws-s3-buckets-writable/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_aws_s3_activities.yml) \| *version*: **2**