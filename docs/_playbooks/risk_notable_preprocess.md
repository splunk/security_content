---
title: "Risk Notable Preprocess"
last_modified_at: 2021-10-22
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Splunk
  - Risk Notable
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

"This playbook prepares a risk notable for investigation by performing the following tasks: 1. Ensures that a risk notable links back to the original notable event with a card pinned to the HUD. 2. Posts a link to this container in the comment field of Splunk ES. 3. Updates the container name, description, and severity to reflect the data in the notable artifact."


- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)
- **Last Updated**: 2021-10-22
- **Author**: Kelby Shelton, Splunk
- **ID**: rn0edc96-ff2b-48b0-9f6f-13da3783fd63

#### Associated Detections


#### How To Implement
tbd

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/risk_notable_preprocess.png)

#### Required field


#### Reference

* [https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack](https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/risk_notable_preprocess.yml) \| *version*: **1**