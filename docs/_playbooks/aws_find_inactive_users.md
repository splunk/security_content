---
title: "AWS Find Inactive Users"
last_modified_at: 2021-11-01
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - AWS IAM
  - Phantom
  - Cloud
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Find AWS accounts that have not been used for a long time (90 days by default). For each unused account, gather additional group and policy information and create an artifact to enable further automation or manual action.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [AWS IAM](https://splunkbase.splunk.com/apps/#/search/AWS IAM/product/soar), [Phantom](https://splunkbase.splunk.com/apps/#/search/Phantom/product/soar)
- **Last Updated**: 2021-11-01
- **Author**: Philip Royer, Splunk
- **ID**: fc0edc76-ff2b-48b0-5f6f-63da6423fd63

#### Associated Detections


#### How To Implement
This playbook is meant to run on a Timer, such as once per week. To adjust the lookback period away from the default, change the number of days to a different negative number in the 'calculate_start_time' block. Note that this playbook will ignore accounts where the password has never been used. These could be unused human accounts or they could be API accounts where the access keys are actively used.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/aws_find_inactive_users.png)

#### Required field


#### Reference

* [https://www.splunk.com/en_us/blog/security/splunk-soar-playbooks-finding-and-disabling-inactive-users-on-aws.html](https://www.splunk.com/en_us/blog/security/splunk-soar-playbooks-finding-and-disabling-inactive-users-on-aws.html)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/aws_find_inactive_users.yml) \| *version*: **1**