---
title: "Detect Zerologon Attack"
last_modified_at: 2020-09-18
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Uncover activity related to the execution of Zerologon CVE-2020-11472, a technique wherein attackers target a Microsoft Windows Domain Controller to reset its computer account password. The result from this attack is attackers can now provide themselves high privileges and take over Domain Controller. The included searches in this Analytic Story are designed to identify attempts to reset Domain Controller Computer Account via exploit code remotely or via the use of tool Mimikatz as payload carrier.

- **ID**: 5d14a962-569e-4578-939f-f386feb63ce4
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-09-18
- **Author**: Rod Soto, Jose Hernandez, Stan Miskowicz, David Dorsey, Shannon Davis Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Computer Changed with Anonymous Account](/endpoint/detect_computer_changed_with_anonymous_account/) | None | Hunting |
| [Detect Credential Dumping through LSASS access](/endpoint/detect_credential_dumping_through_lsass_access/) | None | TTP |
| [Detect Mimikatz Using Loaded Images](/endpoint/detect_mimikatz_using_loaded_images/) | None | TTP |
| [Detect Zerologon via Zeek](/network/detect_zerologon_via_zeek/) | None | TTP |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1003](https://attack.mitre.org/wiki/Technique/T1003)
* [https://github.com/SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)
* [https://www.secura.com/blog/zero-logon](https://www.secura.com/blog/zero-logon)
* [https://nvd.nist.gov/vuln/detail/CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/detect_zerologon_attack.yml) | _version_: **1**