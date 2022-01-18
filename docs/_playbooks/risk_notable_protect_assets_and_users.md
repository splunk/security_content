---
title: "Risk Notable Protect Assets and Users"
last_modified_at: 2021-10-22
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - None
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This playbook attempts to find assets and users from the notable event and match those with assets and identities from Splunk ES. If a match was found and the user has playbooks available to contain entities, the analyst decides which entities to disable or quarantine.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)
- **Last Updated**: 2021-10-22
- **Author**: Kelby Shelton, Splunk
- **ID**: rn0edc96-ff2b-48b0-9f6f-93da3783fd63

#### Associated Detections


#### How To Implement


#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/risk_notable_protect_assets_and_users.png)

#### Required field


#### Reference

* [https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack#Call_child_playbooks_with_the_dynamic_playbook_system](https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack#Call_child_playbooks_with_the_dynamic_playbook_system)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/risk_notable_protect_assets_and_users.yml) \| *version*: **1**