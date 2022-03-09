---
title: "Living Off The Land"
last_modified_at: 2022-02-17
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to search for the presence of an attacker leveraging existing tooling within your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-02-17
- **Author**: Lou Stella, Splunk
- **ID**: 6f7982e2-900b-11ec-a54a-acde48001122

#### Narrative

Living Off The Land refers to an attacker methodology of using software already installed on their target host to achieve their goals. Many utilities that ship with Windows can be used to achieve various goals, with reduced chances of detection by an antivirus software.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | None| TTP |
| [Windows Diskshadow Proxy Execution](/endpoint/windows_diskshadow_proxy_execution/) | None| TTP |
| [WSReset UAC Bypass](/endpoint/wsreset_uac_bypass/) | None| TTP |

#### Reference

* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/living_off_the_land.yml) \| *version*: **1**