---
title: "Internal Host WinRM Response"
last_modified_at: 2021-12-14
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - Windows Remote Management
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Published in response to CVE-2021-44228, this playbook accepts a list of hosts and filenames to remediate on the endpoint. If filenames are provided, the endpoints will be searched and then the user can approve deletion. Then the user is prompted to quarantine the endpoint.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [Windows Remote Management](https://splunkbase.splunk.com/apps/#/search/Windows Remote Management/product/soar)
- **Last Updated**: 2021-12-14
- **Author**: Kelby Shelton, Splunk
- **ID**: 32fd9db5-5201-4b2f-b2c2-9299c7b3495d

#### Associated Detections


#### How To Implement
The winrm asset requires Administrator access to gather certain files.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/internal_host_winrm_log4j_respond.png)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/internal_host_winrm_response.yml) \| *version*: **1**