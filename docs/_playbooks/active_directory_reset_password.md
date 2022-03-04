---
title: "Active Directory Reset password"
last_modified_at: 2020-12-08
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - LDAP
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This playbook resets the password of a potentially compromised user account. First, an analyst is prompted to evaluate the situation and choose whether to reset the account. If they approve, a strong password is generated and the password is reset.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [LDAP](https://splunkbase.splunk.com/apps/#/search/LDAP/product/soar)
- **Last Updated**: 2020-12-08
- **Author**: Philip Royer, Splunk
- **ID**: fc0edc96-ff2b-48b0-9f6f-63da6783fd63

#### Associated Detections


#### How To Implement
This playbook works on artifacts with artifact:*.cef.compromisedUserName which can be created as shown in the playbook "recorded_future_handle_leaked_credentials" - The prompt is hard-coded to use "admin" as the user, so change it to the correct user or role

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/activedirectory_reset_password.png)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/active_directory_reset_password.yml) \| *version*: **1**