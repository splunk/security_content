---
title: "Credential Dumping"
last_modified_at: 2020-02-04
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Uncover activity consistent with credential dumping, a technique wherein attackers compromise systems and attempt to obtain and exfiltrate passwords. The threat actors use these pilfered credentials to further escalate privileges and spread throughout a target environment. The included searches in this Analytic Story are designed to identify attempts to credential dumping.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-04
- **Author**: Rico Valdez, Splunk
- **ID**: 854d78bf-d0e2-4f4e-b05c-640905f86d7a

#### Narrative

Credential dumping&#151;gathering credentials from a target system, often hashed or encrypted&#151;is a common attack technique. Even though the credentials may not be in plain text, an attacker can still exfiltrate the data and set to cracking it offline, on their own systems. The threat actors target a variety of sources to extract them, including the Security Accounts Manager (SAM), Local Security Authority (LSA), NTDS from Domain Controllers, or the Group Policy Preference (GPP) files.\
Once attackers obtain valid credentials, they use them to move throughout a target network with ease, discovering new systems and identifying assets of interest. Credentials obtained in this manner typically include those of privileged users, which may provide access to more sensitive information and system operations.\
The detection searches in this Analytic Story monitor access to the Local Security Authority Subsystem Service (LSASS) process, the usage of shadowcopies for credential dumping and some other techniques for credential dumping.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Dump LSASS via procdump Rename](/deprecated/dump_lsass_via_procdump_rename/) | None| Hunting |
| [Unsigned Image Loaded by LSASS](/deprecated/unsigned_image_loaded_by_lsass/) | None| TTP |
| [Access LSASS Memory for Dump Creation](/endpoint/access_lsass_memory_for_dump_creation/) | None| TTP |
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/attempted_credential_dump_from_registry_via_reg_exe/) | None| TTP |
| [Create Remote Thread into LSASS](/endpoint/create_remote_thread_into_lsass/) | None| TTP |
| [Creation of lsass Dump with Taskmgr](/endpoint/creation_of_lsass_dump_with_taskmgr/) | None| TTP |
| [Creation of Shadow Copy](/endpoint/creation_of_shadow_copy/) | None| TTP |
| [Creation of Shadow Copy with wmic and powershell](/endpoint/creation_of_shadow_copy_with_wmic_and_powershell/) | None| TTP |
| [Credential Dumping via Copy Command from Shadow Copy](/endpoint/credential_dumping_via_copy_command_from_shadow_copy/) | None| TTP |
| [Credential Dumping via Symlink to Shadow Copy](/endpoint/credential_dumping_via_symlink_to_shadow_copy/) | None| TTP |
| [Detect Copy of ShadowCopy with Script Block Logging](/endpoint/detect_copy_of_shadowcopy_with_script_block_logging/) | None| TTP |
| [Detect Credential Dumping through LSASS access](/endpoint/detect_credential_dumping_through_lsass_access/) | None| TTP |
| [Detect Mimikatz Using Loaded Images](/endpoint/detect_mimikatz_using_loaded_images/) | None| TTP |
| [Dump LSASS via comsvcs DLL](/endpoint/dump_lsass_via_comsvcs_dll/) | None| TTP |
| [Dump LSASS via procdump](/endpoint/dump_lsass_via_procdump/) | None| TTP |
| [Enable WDigest UseLogonCredential Registry](/endpoint/enable_wdigest_uselogoncredential_registry/) | None| TTP |
| [Esentutl SAM Copy](/endpoint/esentutl_sam_copy/) | None| Hunting |
| [Extraction of Registry Hives](/endpoint/extraction_of_registry_hives/) | None| TTP |
| [Ntdsutil Export NTDS](/endpoint/ntdsutil_export_ntds/) | None| TTP |
| [SAM Database File Access Attempt](/endpoint/sam_database_file_access_attempt/) | None| Hunting |
| [SecretDumps Offline NTDS Dumping Tool](/endpoint/secretdumps_offline_ntds_dumping_tool/) | None| TTP |
| [Set Default PowerShell Execution Policy To Unrestricted or Bypass](/endpoint/set_default_powershell_execution_policy_to_unrestricted_or_bypass/) | None| TTP |
| [Windows Hunting System Account Targeting Lsass](/endpoint/windows_hunting_system_account_targeting_lsass/) | None| Hunting |
| [Windows Non-System Account Targeting Lsass](/endpoint/windows_non-system_account_targeting_lsass/) | None| TTP |
| [Windows Possible Credential Dumping](/endpoint/windows_possible_credential_dumping/) | None| TTP |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1003](https://attack.mitre.org/wiki/Technique/T1003)
* [https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/credential_dumping.yml) \| *version*: **3**