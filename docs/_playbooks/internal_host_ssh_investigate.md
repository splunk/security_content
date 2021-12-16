---
title: "Internal Host SSH Investigate"
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

Investigate an internal unix host using SSH. This pushes a bash script to the endpoint and runs it, collecting generic information about the processes, user activity, and network activity. This includes the process list, login history, cron jobs, and open sockets. The results are zipped up in .csv files and added to the vault for an analyst to review.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [SSH](https://splunkbase.splunk.com/apps/#/search/SSH/product/soar)
- **Last Updated**: 2021-12-14
- **Author**: Philip Royer, Splunk
- **ID**: fdb65816-6688-41d8-8698-755b7b4ec44e

#### Associated Detections


#### How To Implement
The ssh asset requires sudo access to view the processes with open sockets.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/internal_host_ssh_investigate.png)

#### Required field


#### Reference

* [https://github.com/Neo23x0/Fenrir/blob/master/fenrir.sh](https://github.com/Neo23x0/Fenrir/blob/master/fenrir.sh)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/internal_host_ssh_investigate.yml) \| *version*: **1**