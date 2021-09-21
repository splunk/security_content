---
title: "Orangeworm Attack Group"
last_modified_at: 2020-01-22
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Detect activities and various techniques associated with the Orangeworm Attack Group, a group that frequently targets the healthcare industry.

- **ID**: bb9f5ed2-916e-4364-bb6d-97c370efcf52
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-01-22
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [First Time Seen Running Windows Service](/endpoint/first_time_seen_running_windows_service/) | None | Anomaly |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | None | TTP |

#### Reference

* [https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia](https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia)
* [https://www.infosecurity-magazine.com/news/healthcare-targeted-by-hacker/](https://www.infosecurity-magazine.com/news/healthcare-targeted-by-hacker/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/orangeworm_attack_group.yml) \| *version*: **2**