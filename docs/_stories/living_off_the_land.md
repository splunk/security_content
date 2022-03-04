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
  - Endpoint_Processes
  - Endpoint_Registry
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to search for the presence of an attacker leveraging existing tooling within your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses), [Endpoint_Registry](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointRegistry)
- **Last Updated**: 2022-02-17
- **Author**: Lou Stella, Splunk
- **ID**: 6f7982e2-900b-11ec-a54a-acde48001122

#### Narrative

Living Off The Land refers to an attacker methodology of using software already installed on their target host to achieve their goals. Many utilities that ship with Windows can be used to achieve various goals, with reduced chances of detection by an antivirus software.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [WSReset UAC Bypass](/endpoint/wsreset_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Windows Bits Job Persistence](/endpoint/windows_bits_job_persistence/) | [BITS Jobs](/tags/#bits-jobs) | TTP |
| [Windows Bitsadmin Download File](/endpoint/windows_bitsadmin_download_file/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Windows CertUtil Decode File](/endpoint/windows_certutil_decode_file/) | [Deobfuscate/Decode Files or Information](/tags/#deobfuscate/decode-files-or-information) | TTP |
| [Windows CertUtil URLCache Download](/endpoint/windows_certutil_urlcache_download/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Windows CertUtil VerifyCtl Download](/endpoint/windows_certutil_verifyctl_download/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Windows Diskshadow Proxy Execution](/endpoint/windows_diskshadow_proxy_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | Anomaly |
| [Windows Diskshadow Proxy Execution](/endpoint/windows_diskshadow_proxy_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows Eventvwr UAC Bypass](/endpoint/windows_eventvwr_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |
| [Windows MSHTA Child Process](/endpoint/windows_mshta_child_process/) | [Mshta](/tags/#mshta), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows MSHTA Command-Line URL](/endpoint/windows_mshta_command-line_url/) | [Mshta](/tags/#mshta), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows MSHTA Inline HTA Execution](/endpoint/windows_mshta_inline_hta_execution/) | [Mshta](/tags/#mshta), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution) | TTP |
| [Windows PowerShell Start-BitsTransfer](/endpoint/windows_powershell_start-bitstransfer/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Windows Rasautou DLL Execution](/endpoint/windows_rasautou_dll_execution/) | [Dynamic-link Library Injection](/tags/#dynamic-link-library-injection), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Process Injection](/tags/#process-injection) | TTP |
| [Windows Rundll32 Inline HTA Execution](/endpoint/windows_rundll32_inline_hta_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta) | TTP |
| [Windows WSReset UAC Bypass](/endpoint/windows_wsreset_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | Anomaly |

#### Reference

* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/living_off_the_land.yml) \| *version*: **1**