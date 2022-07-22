---
title: "GCP Cross Account Activity"
last_modified_at: 2020-09-01
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Track when a user assumes an IAM role in another GCP account to obtain cross-account access to services and resources in that account. Accessing new roles could be an indication of malicious activity.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-09-01
- **Author**: Rod Soto, Splunk
- **ID**: 0432039c-ef41-4b03-b157-450c25dad1e6

#### Narrative

Google Cloud Platform (GCP) admins manage access to GCP resources and services across the enterprise using GCP Identity and Access Management (IAM) functionality. IAM provides the ability to create and manage GCP users, groups, and roles-each with their own unique set of privileges and defined access to specific resources (such as Compute instances, the GCP Management Console, API, or the command-line interface). Unlike conventional (human) users, IAM roles are potentially assumable by anyone in the organization. They provide users with dynamically created temporary security credentials that expire within a set time period.\
In between the time between when the temporary credentials are issued and when they expire is a period of opportunity, where a user could leverage the temporary credentials to wreak havoc-spin up or remove instances, create new users, elevate privileges, and other malicious activities-throughout the environment.\
This Analytic Story includes searches that will help you monitor your GCP Audit logs logs for evidence of suspicious cross-account activity.  For example, while accessing multiple GCP accounts and roles may be perfectly valid behavior, it may be suspicious when an account requests privileges of an account it has not accessed in the past. After identifying suspicious activities, you can use the provided investigative searches to help you probe more deeply.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [GCP Detect accounts with high risk roles by project](/deprecated/gcp_detect_accounts_with_high_risk_roles_by_project/) | [Valid Accounts](/tags/#valid-accounts)| Hunting |
| [GCP Detect high risk permissions by resource and account](/deprecated/gcp_detect_high_risk_permissions_by_resource_and_account/) | [Valid Accounts](/tags/#valid-accounts)| Hunting |
| [gcp detect oauth token abuse](/deprecated/gcp_detect_oauth_token_abuse/) | [Valid Accounts](/tags/#valid-accounts)| Hunting |
| [GCP Detect gcploit framework](/cloud/gcp_detect_gcploit_framework/) | [Valid Accounts](/tags/#valid-accounts)| TTP |

#### Reference

* [https://cloud.google.com/iam/docs/understanding-service-accounts](https://cloud.google.com/iam/docs/understanding-service-accounts)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/gcp_cross_account_activity.yml) \| *version*: **1**