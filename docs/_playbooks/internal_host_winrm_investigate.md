---
title: "Internal Host WinRM Investigate"
last_modified_at: 2021-12-14
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Windows Remote Management
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Performs a general investigation on key aspects of a windows device using windows remote management. Important files related to the endpoint are generated, bundled into a zip, and copied to the container vault.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Windows Remote Management](https://splunkbase.splunk.com/apps/#/search/Windows Remote Management/product/soar)
- **Last Updated**: 2021-12-14
- **Author**: Kelby Shelton, Splunk
- **ID**: 32fd9db5-5201-4a2f-b2c2-9299c7b3495d

#### Associated Detections


#### How To Implement
The winrm asset requires Administrator access to gather certain files.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/internal_host_winrm_investigate.png)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/internal_host_winrm_investigate.yml) \| *version*: **1**