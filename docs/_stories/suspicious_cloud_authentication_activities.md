---
title: "Suspicious Cloud Authentication Activities"
last_modified_at: 2020-06-04
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your cloud authentication events. Searches within this Analytic Story leverage the recent cloud updates to the Authentication data model to help you stay aware of and investigate suspicious login activity. 

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2020-06-04
- **Author**: Rico Valdez, Splunk
- **ID**: 6380ebbb-55c5-4fce-b754-01fd565fb73c

#### Narrative

It is important to monitor and control who has access to your cloud infrastructure. Detecting suspicious logins will provide good starting points for investigations. Abusive behaviors caused by compromised credentials can lead to direct monetary costs, as you will be billed for any compute activity whether legitimate or otherwise.\
This Analytic Story has data model versions of cloud searches leveraging Authentication data, including those looking for suspicious login activity, and cross-account activity for AWS.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Cross Account Activity From Previously Unseen Account](/cloud/aws_cross_account_activity_from_previously_unseen_account/) | None| Anomaly |
| [Detect AWS Console Login by New User](/cloud/detect_aws_console_login_by_new_user/) | None| Hunting |
| [Detect AWS Console Login by User from New City](/cloud/detect_aws_console_login_by_user_from_new_city/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Hunting |
| [Detect AWS Console Login by User from New Country](/cloud/detect_aws_console_login_by_user_from_new_country/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Hunting |
| [Detect AWS Console Login by User from New Region](/cloud/detect_aws_console_login_by_user_from_new_region/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions)| Hunting |

#### Reference

* [https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/](https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/)
* [https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_cloud_authentication_activities.yml) \| *version*: **1**