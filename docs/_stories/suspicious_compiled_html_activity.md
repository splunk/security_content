---
title: "Suspicious Compiled HTML Activity"
last_modified_at: 2021-02-11
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **ID**: a09db4d1-3827-4833-87b8-3a397e532119
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-11
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect HTML Help Renamed](/endpoint/detect_html_help_renamed/) | None | TTP |
| [Detect HTML Help Spawn Child Process](/endpoint/detect_html_help_spawn_child_process/) | None | TTP |
| [Detect HTML Help URL in Command Line](/endpoint/detect_html_help_url_in_command_line/) | None | TTP |
| [Detect HTML Help Using InfoTech Storage Handlers](/endpoint/detect_html_help_using_infotech_storage_handlers/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://redcanary.com/blog/introducing-atomictestharnesses/](https://redcanary.com/blog/introducing-atomictestharnesses/)
* [https://attack.mitre.org/techniques/T1218/001/](https://attack.mitre.org/techniques/T1218/001/)
* [https://docs.microsoft.com/en-us/windows/win32/api/htmlhelp/nf-htmlhelp-htmlhelpa](https://docs.microsoft.com/en-us/windows/win32/api/htmlhelp/nf-htmlhelp-htmlhelpa)



_version_: 1