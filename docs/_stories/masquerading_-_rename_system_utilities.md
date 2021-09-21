---
title: "Masquerading - Rename System Utilities"
last_modified_at: 2021-04-26
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities.

- **ID**: f0258af4-a6ae-11eb-b3c2-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-26
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Execution of File with Multiple Extensions](/endpoint/execution_of_file_with_multiple_extensions/) | None | TTP |
| [Suspicious MSBuild Rename](/endpoint/suspicious_msbuild_rename/) | None | TTP |
| [Suspicious Rundll32 Rename](/endpoint/suspicious_rundll32_rename/) | None | TTP |
| [Suspicious microsoft workflow compiler rename](/endpoint/suspicious_microsoft_workflow_compiler_rename/) | None | TTP |
| [Suspicious msbuild path](/endpoint/suspicious_msbuild_path/) | None | TTP |
| [System Process Running from Unexpected Location](/endpoint/system_process_running_from_unexpected_location/) | None | Anomaly |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | None | TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1036/003/](https://attack.mitre.org/techniques/T1036/003/)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/masquerading_-_rename_system_utilities.yml) | _version_: **1**