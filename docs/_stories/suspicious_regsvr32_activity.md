---
title: "Suspicious Regsvr32 Activity"
last_modified_at: 2021-01-29
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor and detect techniques used by attackers who leverage the regsvr32.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-29
- **Author**: Michael Haag, Splunk
- **ID**: b8bee41e-624f-11eb-ae93-0242ac130002

#### Narrative

One common adversary tactic is to bypass application control solutions via the regsvr32.exe process. This particular bypass was popularized with "SquiblyDoo" using the "scrobj.dll" dll to load .sct scriptlets. This technique is still widely used by adversaries to bypass detection and prevention controls. The file extension of the DLL is irrelevant (it may load a .txt file extension for example). The searches in this story help you detect and investigate suspicious activity that may indicate that an adversary is leveraging regsvr32.exe to execute malicious code. Validate execution Determine if regsvr32.exe executed. Validate the OriginalFileName of regsvr32.exe and further PE metadata. If executed outside of c:\windows\system32 or c:\windows\syswow64, it should be highly suspect. Determine if script code was executed with regsvr32. Situational Awareness - The objective of this step is meant to identify suspicious behavioral indicators related to executed of Script code by regsvr32.exe. Parent process. Is the parent process a known LOLBin? Is the parent process an Office Application? Module loads.  Is regsvr32 loading any suspicious .DLLs? Unsigned or signed from non-standard paths. Network connections. Any network connections? Review the reputation of the remote IP or domain. Retrieval of Script Code - confirm the executed script code is benign or malicious.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Regsvr32 Application Control Bypass](/endpoint/detect_regsvr32_application_control_bypass/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| TTP |
| [Malicious InProcServer32 Modification](/endpoint/malicious_inprocserver32_modification/) | [Regsvr32](/tags/#regsvr32), [Modify Registry](/tags/#modify-registry)| TTP |
| [Regsvr32 Silent and Install Param Dll Loading](/endpoint/regsvr32_silent_and_install_param_dll_loading/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| Anomaly |
| [Regsvr32 with Known Silent Switch Cmdline](/endpoint/regsvr32_with_known_silent_switch_cmdline/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| Anomaly |
| [Suspicious Regsvr32 Register Suspicious Path](/endpoint/suspicious_regsvr32_register_suspicious_path/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1218/010/](https://attack.mitre.org/techniques/T1218/010/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_regsvr32_activity.yml) \| *version*: **1**