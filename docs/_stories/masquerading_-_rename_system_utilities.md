---
title: "Masquerading - Rename System Utilities"
last_modified_at: 2021-04-26
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

Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-26
- **Author**: Michael Haag, Splunk
- **ID**: f0258af4-a6ae-11eb-b3c2-acde48001122

#### Narrative

Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing. It may be possible to bypass those security mechanisms by renaming the utility prior to utilization (ex: rename rundll32.exe). An alternative case occurs when a legitimate utility is copied or moved to a different directory and renamed to avoid detections based on system utilities executing from non-standard paths.\
The following content is here to assist with binaries within `system32` or `syswow64` being moved to a new location or an adversary bringing a the binary in to execute.\
There will be false positives as some native Windows processes are moved or ran by third party applications from different paths. If file names are mismatched between the file name on disk and that of the binarys PE metadata, this is a likely indicator that a binary was renamed after it was compiled. Collecting and comparing disk and resource filenames for binaries by looking to see if the InternalName, OriginalFilename, and or ProductName match what is expected could provide useful leads, but may not always be indicative of malicious activity. Do not focus on the possible names a file could have, but instead on the command-line arguments that are known to be used and are distinct because it will have a better rate of detection.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Execution of File With Spaces Before Extension](/deprecated/execution_of_file_with_spaces_before_extension/) | None| TTP |
| [Suspicious Rundll32 Rename](/deprecated/suspicious_rundll32_rename/) | None| Hunting |
| [Execution of File with Multiple Extensions](/endpoint/execution_of_file_with_multiple_extensions/) | None| TTP |
| [Sdelete Application Execution](/endpoint/sdelete_application_execution/) | None| TTP |
| [Suspicious microsoft workflow compiler rename](/endpoint/suspicious_microsoft_workflow_compiler_rename/) | None| Hunting |
| [Suspicious msbuild path](/endpoint/suspicious_msbuild_path/) | None| TTP |
| [Suspicious MSBuild Rename](/endpoint/suspicious_msbuild_rename/) | None| TTP |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | None| TTP |
| [Windows DotNet Binary in Non Standard Path](/endpoint/windows_dotnet_binary_in_non_standard_path/) | None| TTP |
| [Windows InstallUtil in Non Standard Path](/endpoint/windows_installutil_in_non_standard_path/) | None| TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1036/003/](https://attack.mitre.org/techniques/T1036/003/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/masquerading_-_rename_system_utilities.yml) \| *version*: **1**