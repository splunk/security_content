---
title: "Detect Zerologon Attack"
last_modified_at: 2020-09-18
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Uncover activity related to the execution of Zerologon CVE-2020-11472, a technique wherein attackers target a Microsoft Windows Domain Controller to reset its computer account password. The result from this attack is attackers can now provide themselves high privileges and take over Domain Controller. The included searches in this Analytic Story are designed to identify attempts to reset Domain Controller Computer Account via exploit code remotely or via the use of tool Mimikatz as payload carrier.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-09-18
- **Author**: Rod Soto, Jose Hernandez, Stan Miskowicz, David Dorsey, Shannon Davis Splunk
- **ID**: 5d14a962-569e-4578-939f-f386feb63ce4

#### Narrative

This attack is a privilege escalation technique, where attacker targets a Netlogon secure channel connection to a domain controller, using Netlogon Remote Protocol (MS-NRPC). This vulnerability exposes vulnerable Windows Domain Controllers to be targeted via unaunthenticated RPC calls which eventually reset Domain Contoller computer account ($) providing the attacker the opportunity to exfil domain controller credential secrets and assign themselve high privileges that can lead to domain controller and potentially complete network takeover. The detection searches in this Analytic Story use Windows Event viewer events and Sysmon events to detect attack execution, these searches monitor access to the Local Security Authority Subsystem Service (LSASS) process which is an indicator of the use of Mimikatz tool which has bee updated to carry this attack payload.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Credential Dumping through LSASS access](/endpoint/detect_credential_dumping_through_lsass_access/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Detect Mimikatz Using Loaded Images](/endpoint/detect_mimikatz_using_loaded_images/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Windows Possible Credential Dumping](/endpoint/windows_possible_credential_dumping/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Detect Computer Changed with Anonymous Account](/endpoint/detect_computer_changed_with_anonymous_account/) | [Exploitation of Remote Services](/tags/#exploitation-of-remote-services)| Hunting |
| [Detect Zerologon via Zeek](/network/detect_zerologon_via_zeek/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1003](https://attack.mitre.org/wiki/Technique/T1003)
* [https://github.com/SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)
* [https://www.secura.com/blog/zero-logon](https://www.secura.com/blog/zero-logon)
* [https://nvd.nist.gov/vuln/detail/CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/detect_zerologon_attack.yml) \| *version*: **1**