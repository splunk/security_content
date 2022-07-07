---
title: "Windows System Binary Proxy Execution MSIExec"
last_modified_at: 2022-06-16
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

Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi).

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-16
- **Author**: Michael Haag, Splunk
- **ID**: bea2e16b-4599-46ad-a95b-116078726c68

#### Narrative

Adversaries may abuse msiexec.exe to launch local or network accessible MSI files. Msiexec.exe can also execute DLLs. Since it may be signed and native on Windows systems, msiexec.exe can be used to bypass application control solutions that do not account for its potential abuse. Msiexec.exe execution may also be elevated to SYSTEM privileges if the AlwaysInstallElevated policy is enabled.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows MSIExec DLLRegisterServer](/endpoint/windows_msiexec_dllregisterserver/) | [Msiexec](/tags/#msiexec)| TTP |
| [Windows MSIExec Remote Download](/endpoint/windows_msiexec_remote_download/) | [Msiexec](/tags/#msiexec)| TTP |
| [Windows MSIExec Spawn Discovery Command](/endpoint/windows_msiexec_spawn_discovery_command/) | [Msiexec](/tags/#msiexec)| TTP |
| [Windows MSIExec Unregister DLLRegisterServer](/endpoint/windows_msiexec_unregister_dllregisterserver/) | [Msiexec](/tags/#msiexec)| TTP |
| [Windows MSIExec With Network Connections](/endpoint/windows_msiexec_with_network_connections/) | [Msiexec](/tags/#msiexec)| TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1218/007/](https://attack.mitre.org/techniques/T1218/007/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_system_binary_proxy_execution_msiexec.yml) \| *version*: **1**