---
title: "Trusted Developer Utilities Proxy Execution MSBuild"
last_modified_at: 2021-01-21
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor and detect techniques used by attackers who leverage the msbuild.exe process to execute malicious code.

- **ID**: be3418e2-551b-11eb-ae93-0242ac130002
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-21
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Suspicious MSBuild Rename](/endpoint/suspicious_msbuild_rename/) | None | TTP |
| [Suspicious MSBuild Spawn](/endpoint/suspicious_msbuild_spawn/) | None | TTP |
| [Suspicious msbuild path](/endpoint/suspicious_msbuild_path/) | None | TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md)
* [https://github.com/infosecn1nja/MaliciousMacroMSBuild](https://github.com/infosecn1nja/MaliciousMacroMSBuild)
* [https://github.com/xorrior/RandomPS-Scripts/blob/master/Invoke-ExecuteMSBuild.ps1](https://github.com/xorrior/RandomPS-Scripts/blob/master/Invoke-ExecuteMSBuild.ps1)
* [https://lolbas-project.github.io/lolbas/Binaries/Msbuild/](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)
* [https://github.com/MHaggis/CBR-Queries/blob/master/msbuild.md](https://github.com/MHaggis/CBR-Queries/blob/master/msbuild.md)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/trusted_developer_utilities_proxy_execution_msbuild.yml) | _version_: **1**