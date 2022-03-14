---
title: "Netsh Abuse"
last_modified_at: 2017-01-05
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect activities and various techniques associated with the abuse of `netsh.exe`, which can disable local firewall settings or set up a remote connection to a host from an infected system.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2017-01-05
- **Author**: Bhavin Patel, Splunk
- **ID**: 2b1800dd-92f9-47ec-a981-fdf1351e5f65

#### Narrative

It is a common practice for attackers of all types to leverage native Windows tools and functionality to execute commands for malicious reasons. One such tool on Windows OS is `netsh.exe`,a command-line scripting utility that allows you to--either locally or remotely--display or modify the network configuration of a computer that is currently running. `Netsh.exe` can be used to discover and disable local firewall settings. It can also be used to set up a remote connection to a host from an infected system.\
To get started, run the detection search to identify parent processes of `netsh.exe`.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Processes created by netsh](/deprecated/processes_created_by_netsh/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall)| TTP |
| [Processes launching netsh](/endpoint/processes_launching_netsh/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses)| TTP |

#### Reference

* [https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb490939(v=technet.10)](https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb490939(v=technet.10))
* [https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html](https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html)
* [http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html](http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/netsh_abuse.yml) \| *version*: **1**