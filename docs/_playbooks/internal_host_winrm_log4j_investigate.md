---
title: "Internal Host WinRM Log4j Investigate"
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

Published in response to CVE-2021-44228, this playbook uses WinRM to scan Windows endpoints for the presence of "jndilookup.class" in all .jar files. The presence of that string could indicate a log4j vulnerability.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Windows Remote Management](https://splunkbase.splunk.com/apps/#/search/Windows Remote Management/product/soar)
- **Last Updated**: 2021-12-14
- **Author**: Kelby Shelton, Splunk
- **ID**: 2cf7c9f4-b273-44f6-a27c-e0db668ff05a

#### Associated Detections


#### How To Implement
The winrm asset requires Administrator access to scan the whole file system.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/internal_host_winrm_log4j_investigate.png)

#### Required field


#### Reference

* [https://twitter.com/CyberRaiju/status/1469505677580124160](https://twitter.com/CyberRaiju/status/1469505677580124160)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/internal_host_winrm_log4j_investigate.yml) \| *version*: **1**