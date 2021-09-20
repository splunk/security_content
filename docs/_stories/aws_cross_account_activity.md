---
title: "AWS Cross Account Activity"
last_modified_at: 2018-06-04
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Track when a user assumes an IAM role in another AWS account to obtain cross-account access to services and resources in that account. Accessing new roles could be an indication of malicious activity.

- **ID**: 2f2f610a-d64d-48c2-b57c-967a2b49ab5a
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-06-04
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [aws detect attach to role policy](/cloud/aws_detect_attach_to_role_policy/) | None | Hunting |
| [aws detect permanent key creation](/cloud/aws_detect_permanent_key_creation/) | None | Hunting |
| [aws detect role creation](/cloud/aws_detect_role_creation/) | None | Hunting |
| [aws detect sts assume role abuse](/cloud/aws_detect_sts_assume_role_abuse/) | None | Hunting |
| [aws detect sts get session token abuse](/cloud/aws_detect_sts_get_session_token_abuse/) | None | Hunting |

#### Kill Chain Phase



#### Reference

* [https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/](https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/)



_version_: 1