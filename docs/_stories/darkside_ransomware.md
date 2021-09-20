---
title: "DarkSide Ransomware"
last_modified_at: 2021-05-12
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the DarkSide Ransomware

- **ID**: 507edc74-13d5-4339-878e-b9114ded1f35
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-12
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/attempted_credential_dump_from_registry_via_reg_exe/) | None | TTP |
| [BITSAdmin Download File](/endpoint/bitsadmin_download_file/) | None | TTP |
| [CMLUA Or CMSTPLUA UAC Bypass](/endpoint/cmlua_or_cmstplua_uac_bypass/) | None | TTP |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/certutil_download_with_urlcache_and_split_arguments/) | None | TTP |
| [CertUtil Download With VerifyCtl and Split Arguments](/endpoint/certutil_download_with_verifyctl_and_split_arguments/) | None | TTP |
| [Cobalt Strike Named Pipes](/endpoint/cobalt_strike_named_pipes/) | None | TTP |
| [Delete ShadowCopy With PowerShell](/endpoint/delete_shadowcopy_with_powershell/) | None | TTP |
| [Detect Mimikatz Using Loaded Images](/endpoint/detect_mimikatz_using_loaded_images/) | None | TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | None | TTP |
| [Detect RClone Command-Line Usage](/endpoint/detect_rclone_command-line_usage/) | None | TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | None | TTP |
| [Detect Renamed RClone](/endpoint/detect_renamed_rclone/) | None | TTP |
| [Extract SAM from Registry](/endpoint/extract_sam_from_registry/) | None | TTP |
| [Ransomware Notes bulk creation](/endpoint/ransomware_notes_bulk_creation/) | None | Anomaly |
| [SLUI RunAs Elevated](/endpoint/slui_runas_elevated/) | None | TTP |
| [SLUI Spawning a Process](/endpoint/slui_spawning_a_process/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://www.splunk.com/en_us/blog/security/the-darkside-of-the-ransomware-pipeline.htmlbig-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/](https://www.splunk.com/en_us/blog/security/the-darkside-of-the-ransomware-pipeline.htmlbig-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/)
* [https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html](https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html)



_version_: 1