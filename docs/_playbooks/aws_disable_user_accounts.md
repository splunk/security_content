---
title: "AWS Disable User Accounts"
last_modified_at: 2021-11-01
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - AWS IAM
  - Cloud
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Disable a list of AWS IAM user accounts. After checking the list of accounts against an allowlist and confirming with an analyst, each account is disabled. The change can be reversed with the `enable user` action.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [AWS IAM](https://splunkbase.splunk.com/apps/#/search/AWS IAM/product/soar)
- **Last Updated**: 2021-11-01
- **Author**: Philip Royer, Splunk
- **ID**: fc0edc75-ff2b-48c0-5f6f-63da6423fd63

#### Associated Detections


#### How To Implement
This playbook works with the community playbook aws_find_inactive_users using the usernames discovered by that playbook. Change the prompt block from admin to the correct analyst user or role. You should create a custom list called aws_inactive_user_allowlist. Any user names in that list will be ignored by this playbook.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/aws_disable_user_accounts.png)

#### Required field


#### Reference

* [https://www.splunk.com/en_us/blog/security/splunk-soar-playbooks-finding-and-disabling-inactive-users-on-aws.html](https://www.splunk.com/en_us/blog/security/splunk-soar-playbooks-finding-and-disabling-inactive-users-on-aws.html)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/aws_disable_user_accounts.yml) \| *version*: **1**