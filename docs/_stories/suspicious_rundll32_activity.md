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
| [Suspicious Rundll32 Rename](/deprecated/suspicious_rundll32_rename/) | None| Hunting |
| [Detect Rundll32 Application Control Bypass - advpack](/endpoint/detect_rundll32_application_control_bypass_-_advpack/) | None| TTP |
| [Detect Rundll32 Application Control Bypass - setupapi](/endpoint/detect_rundll32_application_control_bypass_-_setupapi/) | None| TTP |
| [Detect Rundll32 Application Control Bypass - syssetup](/endpoint/detect_rundll32_application_control_bypass_-_syssetup/) | None| TTP |
| [Dump LSASS via comsvcs DLL](/endpoint/dump_lsass_via_comsvcs_dll/) | None| TTP |
| [Rundll32 Control RunDLL Hunt](/endpoint/rundll32_control_rundll_hunt/) | None| Hunting |
| [Rundll32 Control RunDLL World Writable Directory](/endpoint/rundll32_control_rundll_world_writable_directory/) | None| TTP |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/rundll32_with_no_command_line_arguments_with_network/) | None| TTP |
| [RunDLL Loading DLL By Ordinal](/endpoint/rundll_loading_dll_by_ordinal/) | None| TTP |
| [Suspicious Rundll32 dllregisterserver](/endpoint/suspicious_rundll32_dllregisterserver/) | None| TTP |
| [Suspicious Rundll32 StartW](/endpoint/suspicious_rundll32_startw/) | None| TTP |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/suspicious_rundll32_no_command_line_arguments/) | None| TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_rundll32_activity.yml) \| *version*: **1**