---
title: "Suspicious GCP Storage Activities"
last_modified_at: 2020-08-05
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Use the searches in this Analytic Story to monitor your GCP Storage buckets for evidence of anomalous activity and suspicious behaviors, such as detecting open storage buckets and buckets being accessed from a new IP. The contextual and investigative searches will give you more information, when required.

- **ID**: 4d656b2e-d6be-11ea-87d0-0242ac130003
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-08-05
- **Author**: Shannon Davis, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect GCP Storage access from a new IP](/cloud/detect_gcp_storage_access_from_a_new_ip/) | None | Anomaly |
| [Detect New Open GCP Storage Buckets](/cloud/detect_new_open_gcp_storage_buckets/) | None | TTP |

#### Reference

* [https://cloud.google.com/blog/product/gcp/4-steps-for-hardening-your-cloud-storage-buckets-taking-charge-of-your-security](https://cloud.google.com/blog/product/gcp/4-steps-for-hardening-your-cloud-storage-buckets-taking-charge-of-your-security)
* [https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/](https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_gcp_storage_activities.yml) \| *version*: **1**