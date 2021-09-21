---
title: "Revil Ransomware"
last_modified_at: 2021-06-04
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Revil ransomware, including looking for file writes associated with Revil, encrypting network shares, deleting shadow volume storage, registry key modification, deleting of security logs, and more.

- **ID**: 817cae42-f54b-457a-8a36-fbf45521e29e
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-04
- **Author**: Teoderick Contreras, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Network Discovery In Firewall](/endpoint/allow_network_discovery_in_firewall/) | None | TTP |
| [Delete ShadowCopy With PowerShell](/endpoint/delete_shadowcopy_with_powershell/) | None | TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | None | TTP |
| [Modification Of Wallpaper](/endpoint/modification_of_wallpaper/) | None | TTP |
| [Msmpeng Application DLL Side Loading](/endpoint/msmpeng_application_dll_side_loading/) | None | TTP |
| [Powershell Disable Security Monitoring](/endpoint/powershell_disable_security_monitoring/) | None | TTP |
| [Revil Common Exec Parameter](/endpoint/revil_common_exec_parameter/) | None | TTP |
| [Revil Registry Entry](/endpoint/revil_registry_entry/) | None | TTP |
| [Wbemprox COM Object Execution](/endpoint/wbemprox_com_object_execution/) | None | TTP |

#### Reference

* [https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/](https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/)
* [https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/revil_ransomware.yml) \| *version*: **1**