---
title: "Cobalt Strike"
last_modified_at: 2021-02-16
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Cobalt Strike is threat emulation software. Red teams and penetration testers use Cobalt Strike to demonstrate the risk of a breach and evaluate mature security programs. Most recently, Cobalt Strike has become the choice tool by threat groups due to its ease of use and extensibility.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-16
- **Author**: Michael Haag, Splunk
- **ID**: bcfd17e8-5461-400a-80a2-3b7d1459220c

#### Narrative

This Analytic Story supports you to detect Tactics, Techniques and Procedures (TTPs) from Cobalt Strike. Cobalt Strike has many ways to be enhanced by using aggressor scripts, malleable C2 profiles, default attack packages, and much more. For endpoint behavior, Cobalt Strike is most commonly identified via named pipes, spawn to processes, and DLL function names. Many additional variables are provided for in memory operation of the beacon implant. On the network, depending on the malleable C2 profile used, it is near infinite in the amount of ways to conceal the C2 traffic with Cobalt Strike. Not every query may be specific to Cobalt Strike the tool, but the methodologies and techniques used by it.\
Splunk Threat Research reviewed all publicly available instances of Malleabe C2 Profiles and generated a list of the most commonly used spawnto and pipenames.\
`Spawnto_x86` and `spawnto_x64` is the process that Cobalt Strike will spawn and injects shellcode into.\
Pipename sets the named pipe name used in Cobalt Strikes Beacon SMB C2 traffic.\
With that, new detections were generated focused on these spawnto processes spawning without command line arguments. Similar, the named pipes most commonly used by Cobalt Strike added as a detection. In generating content for Cobalt Strike, the following is considered:\
- Is it normal for spawnto_ value to have no command line arguments? No command line arguments and a network connection?\
- What is the default, or normal, process lineage for spawnto_ value?\
- Does the spawnto_ value make network connections?\
- Is it normal for spawnto_ value to load jscript, vbscript, Amsi.dll, and clr.dll?\
While investigating a detection related to this Analytic Story, keep in mind the parent process, process path, and any file modifications that may occur. Tuning may need to occur to remove any false positives.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Anomalous usage of 7zip](/endpoint/anomalous_usage_of_7zip/) | [Archive via Utility](/tags/#archive-via-utility), [Windows Command Shell](/tags/#windows-command-shell), [Windows Service](/tags/#windows-service), [Process Injection](/tags/#process-injection), [File Transfer Protocols](/tags/#file-transfer-protocols), [Regsvr32](/tags/#regsvr32), [Mshta](/tags/#mshta), [Service Execution](/tags/#service-execution), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Rundll32](/tags/#rundll32), [Scheduled Task](/tags/#scheduled-task), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism), [Exploitation for Client Execution](/tags/#exploitation-for-client-execution), [Web Shell](/tags/#web-shell), [MSBuild](/tags/#msbuild), [Rename System Utilities](/tags/#rename-system-utilities), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Web Protocols](/tags/#web-protocols), [Remote System Discovery](/tags/#remote-system-discovery) | Anomaly |
| [CMD Echo Pipe - Escalation](/endpoint/cmd_echo_pipe_-_escalation/) | [Windows Command Shell](/tags/#windows-command-shell), [Windows Service](/tags/#windows-service) | TTP |
| [Cobalt Strike Named Pipes](/endpoint/cobalt_strike_named_pipes/) | [Process Injection](/tags/#process-injection) | TTP |
| [DLLHost with no Command Line Arguments with Network](/endpoint/dllhost_with_no_command_line_arguments_with_network/) | [Process Injection](/tags/#process-injection) | TTP |
| [Detect Regsvr32 Application Control Bypass](/endpoint/detect_regsvr32_application_control_bypass/) | [Regsvr32](/tags/#regsvr32) | TTP |
| [GPUpdate with no Command Line Arguments with Network](/endpoint/gpupdate_with_no_command_line_arguments_with_network/) | [Process Injection](/tags/#process-injection) | TTP |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/rundll32_with_no_command_line_arguments_with_network/) | [Rundll32](/tags/#rundll32) | TTP |
| [SearchProtocolHost with no Command Line with Network](/endpoint/searchprotocolhost_with_no_command_line_with_network/) | [Process Injection](/tags/#process-injection) | TTP |
| [Services Escalate Exe](/endpoint/services_escalate_exe/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Suspicious DLLHost no Command Line Arguments](/endpoint/suspicious_dllhost_no_command_line_arguments/) | [Process Injection](/tags/#process-injection) | TTP |
| [Suspicious GPUpdate no Command Line Arguments](/endpoint/suspicious_gpupdate_no_command_line_arguments/) | [Process Injection](/tags/#process-injection) | TTP |
| [Suspicious MSBuild Rename](/endpoint/suspicious_msbuild_rename/) | [MSBuild](/tags/#msbuild), [Rename System Utilities](/tags/#rename-system-utilities) | TTP |
| [Suspicious Rundll32 StartW](/endpoint/suspicious_rundll32_startw/) | [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/suspicious_rundll32_no_command_line_arguments/) | [Rundll32](/tags/#rundll32) | TTP |
| [Suspicious SearchProtocolHost no Command Line Arguments](/endpoint/suspicious_searchprotocolhost_no_command_line_arguments/) | [Process Injection](/tags/#process-injection) | TTP |
| [Suspicious microsoft workflow compiler rename](/endpoint/suspicious_microsoft_workflow_compiler_rename/) | [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities) | Hunting |
| [Suspicious msbuild path](/endpoint/suspicious_msbuild_path/) | [MSBuild](/tags/#msbuild), [Rename System Utilities](/tags/#rename-system-utilities) | TTP |

#### Reference

* [https://www.cobaltstrike.com/](https://www.cobaltstrike.com/)
* [https://www.infocyte.com/blog/2020/09/02/cobalt-strike-the-new-favorite-among-thieves/](https://www.infocyte.com/blog/2020/09/02/cobalt-strike-the-new-favorite-among-thieves/)
* [https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/](https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/)
* [https://blog.talosintelligence.com/2020/09/coverage-strikes-back-cobalt-strike-paper.html](https://blog.talosintelligence.com/2020/09/coverage-strikes-back-cobalt-strike-paper.html)
* [https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html](https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html)
* [https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)
* [https://github.com/zer0yu/Awesome-CobaltStrike](https://github.com/zer0yu/Awesome-CobaltStrike)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cobalt_strike.yml) \| *version*: **1**