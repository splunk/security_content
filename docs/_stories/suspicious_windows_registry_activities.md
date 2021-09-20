---
title: "Suspicious Windows Registry Activities"
last_modified_at: 2018-05-31
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor and detect registry changes initiated from remote locations, which can be a sign that an attacker has infiltrated your system.

- **ID**: 2b1800dd-92f9-47dd-a981-fdf1351e5d55
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | None | TTP |
| [Monitor Registry Keys for Print Monitors](/endpoint/monitor_registry_keys_for_print_monitors/) | None | TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | None | TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | None | TTP |
| [Registry Keys for Creating SHIM Databases](/endpoint/registry_keys_for_creating_shim_databases/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://redcanary.com/blog/windows-registry-attacks-threat-detection/](https://redcanary.com/blog/windows-registry-attacks-threat-detection/)
* [https://attack.mitre.org/wiki/Technique/T1112](https://attack.mitre.org/wiki/Technique/T1112)



_version_: 1