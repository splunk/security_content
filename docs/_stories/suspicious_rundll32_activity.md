---
title: "Suspicious Rundll32 Activity"
last_modified_at: 2021-02-03
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

Monitor and detect techniques used by attackers who leverage rundll32.exe to execute arbitrary malicious code.

- **ID**: 80a65487-854b-42f1-80a1-935e4c170694
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-03
- **Author**: Michael Haag, Splunk

#### Narrative

One common adversary tactic is to bypass application control solutions via the rundll32.exe process. Natively, rundll32.exe will load DLLs and is a great example of a Living off the Land Binary. Rundll32.exe may load malicious DLLs by ordinals, function names or directly. The queries in this story focus on loading default DLLs, syssetup.dll, ieadvpack.dll, advpack.dll and setupapi.dll from disk that may be abused by adversaries. Additionally, two analytics developed to assist with identifying DLLRegisterServer, Start and StartW functions being called. The searches in this story help you detect and investigate suspicious activity that may indicate that an adversary is leveraging rundll32.exe to execute malicious code.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Rundll32 Application Control Bypass - advpack](/endpoint/detect_rundll32_application_control_bypass_-_advpack/) | [Rundll32](/tags/#rundll32), [LSASS Memory](/tags/#lsass-memory), [Rename System Utilities](/tags/#rename-system-utilities) | TTP |
| [Detect Rundll32 Application Control Bypass - setupapi](/endpoint/detect_rundll32_application_control_bypass_-_setupapi/) | [Rundll32](/tags/#rundll32) | TTP |
| [Detect Rundll32 Application Control Bypass - syssetup](/endpoint/detect_rundll32_application_control_bypass_-_syssetup/) | [Rundll32](/tags/#rundll32) | TTP |
| [Dump LSASS via comsvcs DLL](/endpoint/dump_lsass_via_comsvcs_dll/) | [LSASS Memory](/tags/#lsass-memory) | TTP |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/rundll32_with_no_command_line_arguments_with_network/) | [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious Rundll32 Rename](/endpoint/suspicious_rundll32_rename/) | [Rundll32](/tags/#rundll32), [Rename System Utilities](/tags/#rename-system-utilities) | TTP |
| [Suspicious Rundll32 StartW](/endpoint/suspicious_rundll32_startw/) | [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious Rundll32 dllregisterserver](/endpoint/suspicious_rundll32_dllregisterserver/) | [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/suspicious_rundll32_no_command_line_arguments/) | [Rundll32](/tags/#rundll32) | TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_rundll32_activity.yml) \| *version*: **1**