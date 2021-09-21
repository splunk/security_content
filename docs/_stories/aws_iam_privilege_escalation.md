---
title: "AWS IAM Privilege Escalation"
last_modified_at: 2021-03-08
toc: true
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

This analytic story contains detections that query your AWS Cloudtrail for activities related to privilege escalation.

- **ID**: ced74200-8465-4bc3-bd2c-22782eec6750
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-03-08
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Create Policy Version to allow all resources](/cloud/aws_create_policy_version_to_allow_all_resources/) | None | TTP |
| [AWS CreateAccessKey](/cloud/aws_createaccesskey/) | None | Hunting |
| [AWS CreateLoginProfile](/cloud/aws_createloginprofile/) | None | TTP |
| [AWS IAM Assume Role Policy Brute Force](/cloud/aws_iam_assume_role_policy_brute_force/) | None | TTP |
| [AWS IAM Delete Policy](/cloud/aws_iam_delete_policy/) | None | Hunting |
| [AWS IAM Failure Group Deletion](/cloud/aws_iam_failure_group_deletion/) | None | Anomaly |
| [AWS IAM Successful Group Deletion](/cloud/aws_iam_successful_group_deletion/) | None | Hunting |
| [AWS SetDefaultPolicyVersion](/cloud/aws_setdefaultpolicyversion/) | None | TTP |
| [AWS UpdateLoginProfile](/cloud/aws_updateloginprofile/) | None | TTP |

#### Reference

* [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
* [https://www.cyberark.com/resources/threat-research-blog/the-cloud-shadow-admin-threat-10-permissions-to-protect](https://www.cyberark.com/resources/threat-research-blog/the-cloud-shadow-admin-threat-10-permissions-to-protect)
* [https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_iam_privilege_escalation.yml) \| *version*: **1**