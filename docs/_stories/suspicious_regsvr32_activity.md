---
title: "Suspicious Regsvr32 Activity"
last_modified_at: 2021-01-29
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor and detect techniques used by attackers who leverage the regsvr32.exe process to execute malicious code.

- **ID**: b8bee41e-624f-11eb-ae93-0242ac130002
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-29
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Regsvr32 Application Control Bypass](/endpoint/detect_regsvr32_application_control_bypass/) | None | TTP |
| [Suspicious Regsvr32 Register Suspicious Path](/endpoint/suspicious_regsvr32_register_suspicious_path/) | None | TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1218/010/](https://attack.mitre.org/techniques/T1218/010/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_regsvr32_activity.yml) \| *version*: **1**