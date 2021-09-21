---
title: "Windows Service Abuse"
last_modified_at: 2017-11-02
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Windows services are often used by attackers for persistence and the ability to load drivers or otherwise interact with the Windows kernel. This Analytic Story helps you monitor your environment for indications that Windows services are being modified or created in a suspicious manner.

- **ID**: 6dbd810e-f66d-414b-8dfc-e46de55cbfe2
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2017-11-02
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [First Time Seen Running Windows Service](/endpoint/first_time_seen_running_windows_service/) | None | Anomaly |
| [Illegal Service and Process Control via Mimikatz modules](/endpoint/illegal_service_and_process_control_via_mimikatz_modules/) | None | TTP |
| [Illegal Service and Process Control via PowerSploit modules](/endpoint/illegal_service_and_process_control_via_powersploit_modules/) | None | TTP |
| [Reg exe Manipulating Windows Services Registry Keys](/endpoint/reg_exe_manipulating_windows_services_registry_keys/) | None | TTP |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | None | TTP |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1050](https://attack.mitre.org/wiki/Technique/T1050)
* [https://attack.mitre.org/wiki/Technique/T1031](https://attack.mitre.org/wiki/Technique/T1031)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/windows_service_abuse.yml) | _version_: **3**