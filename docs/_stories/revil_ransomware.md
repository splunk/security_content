---
title: "Revil Ransomware"
last_modified_at: 2021-06-04
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Revil ransomware, including looking for file writes associated with Revil, encrypting network shares, deleting shadow volume storage, registry key modification, deleting of security logs, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-04
- **Author**: Teoderick Contreras, Splunk
- **ID**: 817cae42-f54b-457a-8a36-fbf45521e29e

#### Narrative

Revil ransomware is a RaaS,that a single group may operates and manges the development of this ransomware. It involve the use of ransomware payloads along with exfiltration of data. Malicious actors demand payment for ransome of data and threaten deletion and exposure of exfiltrated data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Network Discovery In Firewall](/endpoint/allow_network_discovery_in_firewall/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Delete ShadowCopy With PowerShell](/endpoint/delete_shadowcopy_with_powershell/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Modification Of Wallpaper](/endpoint/modification_of_wallpaper/) | [Defacement](/tags/#defacement)| TTP |
| [Msmpeng Application DLL Side Loading](/endpoint/msmpeng_application_dll_side_loading/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow)| TTP |
| [Powershell Disable Security Monitoring](/endpoint/powershell_disable_security_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Revil Common Exec Parameter](/endpoint/revil_common_exec_parameter/) | [User Execution](/tags/#user-execution)| TTP |
| [Revil Registry Entry](/endpoint/revil_registry_entry/) | [Modify Registry](/tags/#modify-registry)| TTP |
| [Wbemprox COM Object Execution](/endpoint/wbemprox_com_object_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [CMSTP](/tags/#cmstp)| TTP |

#### Reference

* [https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/](https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/)
* [https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/revil_ransomware.yml) \| *version*: **1**