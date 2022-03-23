---
title: "DarkSide Ransomware"
last_modified_at: 2021-05-12
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the DarkSide Ransomware

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-12
- **Author**: Bhavin Patel, Splunk
- **ID**: 507edc74-13d5-4339-878e-b9114ded1f35

#### Narrative

This story addresses Darkside ransomware. This ransomware payload has many similarities to common ransomware however there are certain items particular to it. The creation of a .TXT log that shows every item being encrypted as well as the creation of ransomware notes and files adding a machine ID created based on CRC32 checksum algorithm. This ransomware payload leaves machines in minimal operation level,enough to browse the attackers websites. A customized URI with leaked information is presented to each victim.This is the ransomware payload that shut down the Colonial pipeline. The story is composed of several detection searches covering similar items to other ransomware payloads and those particular to Darkside payload.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/attempted_credential_dump_from_registry_via_reg_exe/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [BITSAdmin Download File](/endpoint/bitsadmin_download_file/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/certutil_download_with_urlcache_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [CertUtil Download With VerifyCtl and Split Arguments](/endpoint/certutil_download_with_verifyctl_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [CMLUA Or CMSTPLUA UAC Bypass](/endpoint/cmlua_or_cmstplua_uac_bypass/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [CMSTP](/tags/#cmstp)| TTP |
| [Cobalt Strike Named Pipes](/endpoint/cobalt_strike_named_pipes/) | [Process Injection](/tags/#process-injection)| TTP |
| [Delete ShadowCopy With PowerShell](/endpoint/delete_shadowcopy_with_powershell/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Detect Mimikatz Using Loaded Images](/endpoint/detect_mimikatz_using_loaded_images/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Detect RClone Command-Line Usage](/endpoint/detect_rclone_command-line_usage/) | [Automated Exfiltration](/tags/#automated-exfiltration)| TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution)| Hunting |
| [Detect Renamed RClone](/endpoint/detect_renamed_rclone/) | [Automated Exfiltration](/tags/#automated-exfiltration)| Hunting |
| [Extraction of Registry Hives](/endpoint/extraction_of_registry_hives/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Ransomware Notes bulk creation](/endpoint/ransomware_notes_bulk_creation/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact)| Anomaly |
| [SLUI RunAs Elevated](/endpoint/slui_runas_elevated/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [SLUI Spawning a Process](/endpoint/slui_spawning_a_process/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [Windows Possible Credential Dumping](/endpoint/windows_possible_credential_dumping/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |

#### Reference

* [https://www.splunk.com/en_us/blog/security/the-darkside-of-the-ransomware-pipeline.htmlbig-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/](https://www.splunk.com/en_us/blog/security/the-darkside-of-the-ransomware-pipeline.htmlbig-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/)
* [https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html](https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/darkside_ransomware.yml) \| *version*: **1**