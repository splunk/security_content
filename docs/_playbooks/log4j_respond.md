---
title: "Log4j Respond"
last_modified_at: 2021-12-14
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - Log4J
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Published in response to CVE-2021-44228, this playbook is meant to be launched after log4j_investigate. In this playbook, the risk from exploited hosts can be mitigated by optionally deleting malicious files from the hosts, blocking outbound network connections from the hosts, and/or shutting down the hosts

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2021-12-14
- **Author**: Philip Royer, Splunk
- **ID**: e609d729-4076-421a-b8f7-9e545d000381

#### Associated Detections

* [Curl Download and Bash Execution](/detection/curl_download_and_bash_execution/)
* [Wget Download and Bash Execution](/detection/wget_download_and_bash_execution/)
* [Linux Java Spawning Shell](/detection/linux_java_spawning_shell/)
* [Windows Java Spawning Shell](/detection/windows_java_spawning_shell/)
* [Java Class File download by Java User Agent](/detection/java_class_file_download_by_java_user_agent/)
* [Outbound Network Connection from Java Using Default Ports](/detection/outbound_network_connection_from_java_using_default_ports/)
* [Log4Shell JNDI Payload Injection Attempt](/detection/log4shell_jndi_payload_injection_attempt/)
* [Log4Shell JNDI Payload Injection with Outbound Connection](/detection/log4shell_jndi_payload_injection_with_outbound_connection/)
* [Detect Outbound LDAP Traffic](/detection/detect_outbound_ldap_traffic/)



#### How To Implement
To use this playbook, create a custom list called "log4j_hosts_and_files" with a format in which the first column should be an IP or hostname of a potentially affected log4j host, the second should be the operating system family (either unix or windows), and the third should be a full path to a file to delete if there are any. The first two are mandatory and the file is optional. In the block called "enumerate_files_to_delete", change the custom list name from "log4j_hosts_and_files" if needed. If ssh and/or winrm are not the preferred endpoint management methods, these playbooks could be ported to use Google's GRR, osquery,  CrowdStrike's RTR, Carbon Black's EDR API, or similar tools. The artifact scope "all" is used throughout this playbook because the artifact list can be added to as the playbook progresses.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/log4j_respond.png)

#### Required field


#### Reference

* [https://github.com/Neo23x0/Fenrir/blob/master/fenrir.sh](https://github.com/Neo23x0/Fenrir/blob/master/fenrir.sh)
* [https://isc.sans.edu/diary/Log4j++Log4Shell+Followup%3A+What+we+see+and+how+to+defend+%28and+how+to+access+our+data%29/28122](https://isc.sans.edu/diary/Log4j++Log4Shell+Followup%3A+What+we+see+and+how+to+defend+%28and+how+to+access+our+data%29/28122)
* [https://twitter.com/ElektroWolle/status/1469962895849140224?ref_src=twsrc%5Etfw%7Ctwcamp%5Etweetembed%7Ctwterm%5E1469962895849140224%7Ctwgr%5E%7Ctwcon%5Es1_c10&ref_url=https%3A%2F%2Fpublish.twitter.com%2F%3Fquery%3Dhttps3A2F2Ftwitter.com2FElektroWolle2Fstatus2F1469962895849140224widget%3DTweet](https://twitter.com/ElektroWolle/status/1469962895849140224?ref_src=twsrc%5Etfw%7Ctwcamp%5Etweetembed%7Ctwterm%5E1469962895849140224%7Ctwgr%5E%7Ctwcon%5Es1_c10&ref_url=https%3A%2F%2Fpublish.twitter.com%2F%3Fquery%3Dhttps3A2F2Ftwitter.com2FElektroWolle2Fstatus2F1469962895849140224widget%3DTweet)
* [https://blog.cloudflare.com/cve-2021-44228-log4j-rce-0-day-mitigation/](https://blog.cloudflare.com/cve-2021-44228-log4j-rce-0-day-mitigation/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/log4j_respond.yml) \| *version*: **1**