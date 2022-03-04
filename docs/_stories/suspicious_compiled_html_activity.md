---
title: "Suspicious Compiled HTML Activity"
last_modified_at: 2021-02-11
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

Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-11
- **Author**: Michael Haag, Splunk
- **ID**: a09db4d1-3827-4833-87b8-3a397e532119

#### Narrative

Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. CHM content is displayed using underlying components of the Internet Explorer browser loaded by the HTML Help executable program (hh.exe). \
HH.exe relies upon hhctrl.ocx to load CHM topics.This will load upon execution of a chm file. \
During investigation, review all parallel processes and child processes. It is possible for file modification events to occur and it is best to capture the CHM file and decompile it for further analysis. \
Upon usage of InfoTech Storage Handlers, ms-its, its, mk, itss.dll will load.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect HTML Help Renamed](/endpoint/detect_html_help_renamed/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file)| Hunting |
| [Detect HTML Help Spawn Child Process](/endpoint/detect_html_help_spawn_child_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file)| TTP |
| [Detect HTML Help URL in Command Line](/endpoint/detect_html_help_url_in_command_line/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file)| TTP |
| [Detect HTML Help Using InfoTech Storage Handlers](/endpoint/detect_html_help_using_infotech_storage_handlers/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file)| TTP |

#### Reference

* [https://redcanary.com/blog/introducing-atomictestharnesses/](https://redcanary.com/blog/introducing-atomictestharnesses/)
* [https://attack.mitre.org/techniques/T1218/001/](https://attack.mitre.org/techniques/T1218/001/)
* [https://docs.microsoft.com/en-us/windows/win32/api/htmlhelp/nf-htmlhelp-htmlhelpa](https://docs.microsoft.com/en-us/windows/win32/api/htmlhelp/nf-htmlhelp-htmlhelpa)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_compiled_html_activity.yml) \| *version*: **1**