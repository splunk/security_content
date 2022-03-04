---
title: "AWS IAM Privilege Escalation"
last_modified_at: 2021-03-08
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic story contains detections that query your AWS Cloudtrail for activities related to privilege escalation.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-03-08
- **Author**: Bhavin Patel, Splunk
- **ID**: ced74200-8465-4bc3-bd2c-22782eec6750

#### Narrative

Amazon Web Services provides a neat feature called Identity and Access Management (IAM) that enables organizations to manage various AWS services and resources in a secure way. All IAM users have roles, groups and policies associated with them which governs and sets permissions to allow a user to access specific restrictions.\
However, if these IAM policies are misconfigured and have specific combinations of weak permissions; it can allow attackers to escalate their privileges and further compromise the organization. Rhino Security Labs have published comprehensive blogs detailing various AWS Escalation methods. By using this as an inspiration, Splunks research team wants to highlight how these attack vectors look in AWS Cloudtrail logs and provide you with detection queries to uncover these potentially malicious events via this Analytic Story. 

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Create Policy Version to allow all resources](/cloud/aws_create_policy_version_to_allow_all_resources/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts)| TTP |
| [AWS CreateAccessKey](/cloud/aws_createaccesskey/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account)| Hunting |
| [AWS CreateLoginProfile](/cloud/aws_createloginprofile/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account)| TTP |
| [AWS IAM Assume Role Policy Brute Force](/cloud/aws_iam_assume_role_policy_brute_force/) | [Cloud Infrastructure Discovery](/tags/#cloud-infrastructure-discovery), [Brute Force](/tags/#brute-force)| TTP |
| [AWS IAM Delete Policy](/cloud/aws_iam_delete_policy/) | [Account Manipulation](/tags/#account-manipulation)| Hunting |
| [AWS IAM Failure Group Deletion](/cloud/aws_iam_failure_group_deletion/) | [Account Manipulation](/tags/#account-manipulation)| Anomaly |
| [AWS IAM Successful Group Deletion](/cloud/aws_iam_successful_group_deletion/) | [Cloud Groups](/tags/#cloud-groups), [Account Manipulation](/tags/#account-manipulation), [Permission Groups Discovery](/tags/#permission-groups-discovery)| Hunting |
| [AWS SetDefaultPolicyVersion](/cloud/aws_setdefaultpolicyversion/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts)| TTP |
| [AWS UpdateLoginProfile](/cloud/aws_updateloginprofile/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account)| TTP |

#### Reference

* [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
* [https://www.cyberark.com/resources/threat-research-blog/the-cloud-shadow-admin-threat-10-permissions-to-protect](https://www.cyberark.com/resources/threat-research-blog/the-cloud-shadow-admin-threat-10-permissions-to-protect)
* [https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_iam_privilege_escalation.yml) \| *version*: **1**