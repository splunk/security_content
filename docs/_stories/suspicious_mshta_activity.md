---
title: "Suspicious MSHTA Activity"
last_modified_at: 2021-01-20
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **ID**: 2b1800dd-92f9-47dd-a981-fdf13w1q5d55
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-20
- **Author**: Bhavin Patel, Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect MSHTA Url in Command Line](/endpoint/detect_mshta_url_in_command_line/) | None | TTP |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | None | Hunting |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | None | TTP |
| [Detect Rundll32 Inline HTA Execution](/endpoint/detect_rundll32_inline_hta_execution/) | None | TTP |
| [Detect mshta inline hta execution](/endpoint/detect_mshta_inline_hta_execution/) | None | TTP |
| [Detect mshta renamed](/endpoint/detect_mshta_renamed/) | None | TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | None | TTP |
| [Suspicious mshta child process](/endpoint/suspicious_mshta_child_process/) | None | TTP |
| [Suspicious mshta spawn](/endpoint/suspicious_mshta_spawn/) | None | TTP |

#### Reference

* [https://redcanary.com/blog/introducing-atomictestharnesses/](https://redcanary.com/blog/introducing-atomictestharnesses/)
* [https://redcanary.com/blog/windows-registry-attacks-threat-detection/](https://redcanary.com/blog/windows-registry-attacks-threat-detection/)
* [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)
* [https://medium.com/@mbromileyDFIR/malware-monday-aebb456356c5](https://medium.com/@mbromileyDFIR/malware-monday-aebb456356c5)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_mshta_activity.yml) \| *version*: **2**