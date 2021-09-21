---
title: "Netsh Abuse"
last_modified_at: 2017-01-05
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Detect activities and various techniques associated with the abuse of `netsh.exe`, which can disable local firewall settings or set up a remote connection to a host from an infected system.

- **ID**: 2b1800dd-92f9-47ec-a981-fdf1351e5f65
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2017-01-05
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Processes launching netsh](/endpoint/processes_launching_netsh/) | None | TTP |

#### Reference

* [https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb490939(v=technet.10)](https://docs.microsoft.com/en-us/previous-versions/tn-archive/bb490939(v=technet.10))
* [https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html](https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html)
* [http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html](http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/netsh_abuse.yml) | _version_: **1**