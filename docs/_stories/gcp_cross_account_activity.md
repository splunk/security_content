---
title: "GCP Cross Account Activity"
last_modified_at: 2020-09-01
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Track when a user assumes an IAM role in another GCP account to obtain cross-account access to services and resources in that account. Accessing new roles could be an indication of malicious activity.

- **ID**: 0432039c-ef41-4b03-b157-450c25dad1e6
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-09-01
- **Author**: Rod Soto, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [GCP Detect gcploit framework](/cloud/gcp_detect_gcploit_framework/) | None | TTP |

#### Reference

* [https://cloud.google.com/iam/docs/understanding-service-accounts](https://cloud.google.com/iam/docs/understanding-service-accounts)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/gcp_cross_account_activity.yml) | _version_: **1**