---
title: "AWS IAM Privilege Escalation"
excerpt: "This analytic story contains detections that query your AWS Cloudtrail for activities related to privilege escalation."
last_modified_at: 2020-07-27
tags:
  - T1069.003
  - T1078.004
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Adversary Tactics
---

### AWS IAM Privilege Escalation
This analytic story contains detections that query your AWS Cloudtrail for activities related to privilege escalation.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: [T1069.003](https://attack.mitre.org/techniques/T1069.003/), [T1078.004](https://attack.mitre.org/techniques/T1078.004/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1110](https://attack.mitre.org/techniques/T1110/), [T1136.003](https://attack.mitre.org/techniques/T1136.003/), [T1580](https://attack.mitre.org/techniques/T1580/)
- **Last Updated**: 2021-03-08

#### Detection Profile

* [AWS Create Policy Version to allow all resources](detections.md#aws-create-policy-version-to-allow-all-resources)

* [AWS CreateAccessKey](detections.md#aws-createaccesskey)

* [AWS CreateLoginProfile](detections.md#aws-createloginprofile)

* [AWS IAM Assume Role Policy Brute Force](detections.md#aws-iam-assume-role-policy-brute-force)

* [AWS IAM Delete Policy](detections.md#aws-iam-delete-policy)

* [AWS IAM Failure Group Deletion](detections.md#aws-iam-failure-group-deletion)

* [AWS IAM Successful Group Deletion](detections.md#aws-iam-successful-group-deletion)

* [AWS SetDefaultPolicyVersion](detections.md#aws-setdefaultpolicyversion)

* [AWS UpdateLoginProfile](detections.md#aws-updateloginprofile)


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078.004 | Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1136.003 | Cloud Account | Persistence |
| T1580 | Cloud Infrastructure Discovery | Discovery |
| T1110 | Brute Force | Credential Access |
| T1098 | Account Manipulation | Persistence |
| T1069.003 | Cloud Groups | Discovery |

#### Kill Chain Phase

* Actions on Objectives

* Reconnaissance


#### Reference

* https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

* https://www.cyberark.com/resources/threat-research-blog/the-cloud-shadow-admin-threat-10-permissions-to-protect

* https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws


_version_: 1
