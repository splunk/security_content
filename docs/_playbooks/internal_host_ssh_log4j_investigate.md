---
title: "Internal Host SSH Log4j Investigate"
last_modified_at: 2021-12-14
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - SSH
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Investigate an internal unix host using SSH. This pushes a bash script to the endpoint and runs it, collecting information specific to the December 2021 log4j vulnerability disclosure. This includes the java version installed on the host, any running java processes, and the results of a scan for the affected JndiLookup.class file or log4j .jar files.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [SSH](https://splunkbase.splunk.com/apps/#/search/SSH/product/soar)
- **Last Updated**: 2021-12-14
- **Author**: Philip Royer, Splunk
- **ID**: 49b2b88c-8e22-48a6-8808-ace1efcb194b

#### Associated Detections


#### How To Implement
The ssh asset requires sudo access to scan the whole file system.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/internal_host_ssh_log4j_investigate.png)

#### Required field


#### Reference

* [https://github.com/Neo23x0/Fenrir/blob/master/fenrir.sh](https://github.com/Neo23x0/Fenrir/blob/master/fenrir.sh)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/internal_host_ssh_log4j_investigate.yml) \| *version*: **1**