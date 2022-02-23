---
title: "Suspicious MSHTA Activity"
last_modified_at: 2021-01-20
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

Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-20
- **Author**: Bhavin Patel, Michael Haag, Splunk
- **ID**: 1e5a5a53-540b-462a-8fb7-f44a4292f5dc

#### Narrative

One common adversary tactic is to bypass application control solutions via the mshta.exe process, which loads Microsoft HTML applications (mshtml.dll) with the .hta suffix. In these cases, attackers use the trusted Windows utility to proxy execution of malicious files, whether an .hta application, javascript, or VBScript.\
The searches in this story help you detect and investigate suspicious activity that may indicate that an attacker is leveraging mshta.exe to execute malicious code.\
Triage\
Validate execution \
1. Determine if MSHTA.exe executed. Validate the OriginalFileName of MSHTA.exe and further PE metadata. If executed outside of c:\windows\system32 or c:\windows\syswow64, it should be highly suspect.\
1. Determine if script code was executed with MSHTA.\
Situational Awareness\
The objective of this step is meant to identify suspicious behavioral indicators related to executed of Script code by MSHTA.exe.\
1. Parent process. Is the parent process a known LOLBin? Is the parent process an Office Application?\
1. Module loads. Are the known MSHTA.exe modules being loaded by a non-standard application? Is MSHTA loading any suspicious .DLLs?\
1. Network connections. Any network connections? Review the reputation of the remote IP or domain.\
Retrieval of script code\
The objective of this step is to confirm the executed script code is benign or malicious.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect mshta inline hta execution](/endpoint/detect_mshta_inline_hta_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Detect mshta renamed](/endpoint/detect_mshta_renamed/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta)| Hunting |
| [Detect MSHTA Url in Command Line](/endpoint/detect_mshta_url_in_command_line/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell)| Hunting |
| [Detect Rundll32 Inline HTA Execution](/endpoint/detect_rundll32_inline_hta_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Suspicious mshta child process](/endpoint/suspicious_mshta_child_process/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Suspicious mshta spawn](/endpoint/suspicious_mshta_spawn/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |

#### Reference

* [https://redcanary.com/blog/introducing-atomictestharnesses/](https://redcanary.com/blog/introducing-atomictestharnesses/)
* [https://redcanary.com/blog/windows-registry-attacks-threat-detection/](https://redcanary.com/blog/windows-registry-attacks-threat-detection/)
* [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)
* [https://medium.com/@mbromileyDFIR/malware-monday-aebb456356c5](https://medium.com/@mbromileyDFIR/malware-monday-aebb456356c5)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_mshta_activity.yml) \| *version*: **2**