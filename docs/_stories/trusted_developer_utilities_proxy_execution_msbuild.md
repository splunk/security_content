---
title: "Trusted Developer Utilities Proxy Execution MSBuild"
last_modified_at: 2021-01-21
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor and detect techniques used by attackers who leverage the msbuild.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-21
- **Author**: Michael Haag, Splunk
- **ID**: be3418e2-551b-11eb-ae93-0242ac130002

#### Narrative

Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio and is native to Windows. It handles XML formatted project files that define requirements for loading and building various platforms and configurations.\
The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into an XML project file. MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application control defenses that are configured to allow MSBuild.exe execution.\
The searches in this story help you detect and investigate suspicious activity that may indicate that an adversary is leveraging msbuild.exe to execute malicious code.\
Triage\
Validate execution\
1. Determine if MSBuild.exe executed. Validate the OriginalFileName of MSBuild.exe and further PE metadata.\
1. Determine if script code was executed with MSBuild.\
Situational Awareness\
The objective of this step is meant to identify suspicious behavioral indicators related to executed of Script code by MSBuild.exe.\
1. Parent process. Is the parent process a known LOLBin? Is the parent process an Office Application?\
1. Module loads. Are the known MSBuild.exe modules being loaded by a non-standard application? Is MSbuild loading any suspicious .DLLs?\
1. Network connections. Any network connections? Review the reputation of the remote IP or domain.\
Retrieval of script code\
The objective of this step is to confirm the executed script code is benign or malicious.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [MSBuild Suspicious Spawned By Script Process](/endpoint/msbuild_suspicious_spawned_by_script_process/) | [MSBuild](/tags/#msbuild), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution) | TTP |
| [Suspicious MSBuild Rename](/endpoint/suspicious_msbuild_rename/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | TTP |
| [Suspicious MSBuild Spawn](/endpoint/suspicious_msbuild_spawn/) | [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [MSBuild](/tags/#msbuild) | TTP |
| [Suspicious msbuild path](/endpoint/suspicious_msbuild_path/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md)
* [https://github.com/infosecn1nja/MaliciousMacroMSBuild](https://github.com/infosecn1nja/MaliciousMacroMSBuild)
* [https://github.com/xorrior/RandomPS-Scripts/blob/master/Invoke-ExecuteMSBuild.ps1](https://github.com/xorrior/RandomPS-Scripts/blob/master/Invoke-ExecuteMSBuild.ps1)
* [https://lolbas-project.github.io/lolbas/Binaries/Msbuild/](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)
* [https://github.com/MHaggis/CBR-Queries/blob/master/msbuild.md](https://github.com/MHaggis/CBR-Queries/blob/master/msbuild.md)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/trusted_developer_utilities_proxy_execution_msbuild.yml) \| *version*: **1**