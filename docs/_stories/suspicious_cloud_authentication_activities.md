---
title: "Suspicious Cloud Authentication Activities"
last_modified_at: 2020-06-04
toc: true
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---

#### Description

Monitor your cloud authentication events. Searches within this Analytic Story leverage the recent cloud updates to the Authentication data model to help you stay aware of and investigate suspicious login activity. 

- **ID**: 6380ebbb-55c5-4fce-b754-01fd565fb73c
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2020-06-04
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Cross Account Activity From Previously Unseen Account](/cloud/aws_cross_account_activity_from_previously_unseen_account/) | None | Anomaly |
| [Detect AWS Console Login by New User](/cloud/detect_aws_console_login_by_new_user/) | None | Hunting |
| [Detect AWS Console Login by User from New City](/cloud/detect_aws_console_login_by_user_from_new_city/) | None | Hunting |
| [Detect AWS Console Login by User from New Country](/cloud/detect_aws_console_login_by_user_from_new_country/) | None | Hunting |
| [Detect AWS Console Login by User from New Region](/cloud/detect_aws_console_login_by_user_from_new_region/) | None | Hunting |

#### Kill Chain Phase



#### Reference

* [https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/](https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/)
* [https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)



_version_: 1