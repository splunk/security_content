---
title: "Risk Notable Block Indicators"
last_modified_at: 2021-10-22
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - None
  - Risk Notable
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This playbook handles locating indicators marked for blocking and determining if any blocking playbooks exist. If there is a match to the appropriate tags in the playbook, a filter block routes the name of the playbook to launch to a code block.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)
- **Last Updated**: 2021-10-22
- **Author**: Kelby Shelton, Splunk
- **ID**: rn0edc96-ff2b-48b0-9f6f-83da3783fd63

#### Associated Detections


#### How To Implement
tbd

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/risk_notable_block_indicators.png)

#### Required field


#### Reference

* [https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack#Call_child_playbooks_with_the_dynamic_playbook_system](https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack#Call_child_playbooks_with_the_dynamic_playbook_system)
* [https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack#Indicator_tagging_system](https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack#Indicator_tagging_system)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/risk_notable_block_indicators.yml) \| *version*: **1**