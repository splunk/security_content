---
title: "Suspicious Rundll32 Activity"
last_modified_at: 2021-02-03
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor and detect techniques used by attackers who leverage rundll32.exe to execute arbitrary malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-03
- **Author**: Michael Haag, Splunk
- **ID**: 80a65487-854b-42f1-80a1-935e4c170694

#### Narrative

One common adversary tactic is to bypass application control solutions via the rundll32.exe process. Natively, rundll32.exe will load DLLs and is a great example of a Living off the Land Binary. Rundll32.exe may load malicious DLLs by ordinals, function names or directly. The queries in this story focus on loading default DLLs, syssetup.dll, ieadvpack.dll, advpack.dll and setupapi.dll from disk that may be abused by adversaries. Additionally, two analytics developed to assist with identifying DLLRegisterServer, Start and StartW functions being called. The searches in this story help you detect and investigate suspicious activity that may indicate that an adversary is leveraging rundll32.exe to execute malicious code.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Suspicious Rundll32 Rename](/deprecated/suspicious_rundll32_rename/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Masquerading](/tags/#masquerading), [Rundll32](/tags/#rundll32), [Rename System Utilities](/tags/#rename-system-utilities)| Hunting |
| [Detect Rundll32 Application Control Bypass - advpack](/endpoint/detect_rundll32_application_control_bypass_-_advpack/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Detect Rundll32 Application Control Bypass - setupapi](/endpoint/detect_rundll32_application_control_bypass_-_setupapi/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Detect Rundll32 Application Control Bypass - syssetup](/endpoint/detect_rundll32_application_control_bypass_-_syssetup/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Dump LSASS via comsvcs DLL](/endpoint/dump_lsass_via_comsvcs_dll/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Rundll32 Control RunDLL Hunt](/endpoint/rundll32_control_rundll_hunt/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| Hunting |
| [Rundll32 Control RunDLL World Writable Directory](/endpoint/rundll32_control_rundll_world_writable_directory/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/rundll32_with_no_command_line_arguments_with_network/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [RunDLL Loading DLL By Ordinal](/endpoint/rundll_loading_dll_by_ordinal/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Suspicious Rundll32 dllregisterserver](/endpoint/suspicious_rundll32_dllregisterserver/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Suspicious Rundll32 StartW](/endpoint/suspicious_rundll32_startw/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/suspicious_rundll32_no_command_line_arguments/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_rundll32_activity.yml) \| *version*: **1**