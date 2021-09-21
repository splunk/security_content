---
title: "Malicious PowerShell"
last_modified_at: 2017-08-23
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Attackers are finding stealthy ways "live off the land," leveraging utilities and tools that come standard on the endpoint--such as PowerShell--to achieve their goals without downloading binary files. These searches can help you detect and investigate PowerShell command-line options that may be indicative of malicious intent.

- **ID**: 2c8ff66e-0b57-42af-8ad7-912438a403fc
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2017-08-23
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadFile](/endpoint/any_powershell_downloadfile/) | None | TTP |
| [Any Powershell DownloadString](/endpoint/any_powershell_downloadstring/) | None | TTP |
| [Credential Extraction indicative of use of DSInternals credential conversion modules](/endpoint/credential_extraction_indicative_of_use_of_dsinternals_credential_conversion_modules/) | None | TTP |
| [Credential Extraction indicative of use of DSInternals modules](/endpoint/credential_extraction_indicative_of_use_of_dsinternals_modules/) | None | TTP |
| [Credential Extraction indicative of use of PowerSploit modules](/endpoint/credential_extraction_indicative_of_use_of_powersploit_modules/) | None | TTP |
| [Credential Extraction via Get-ADDBAccount module present in PowerSploit and DSInternals](/endpoint/credential_extraction_via_get-addbaccount_module_present_in_powersploit_and_dsinternals/) | None | TTP |
| [Detect Empire with PowerShell Script Block Logging](/endpoint/detect_empire_with_powershell_script_block_logging/) | None | TTP |
| [Detect Mimikatz With PowerShell Script Block Logging](/endpoint/detect_mimikatz_with_powershell_script_block_logging/) | None | TTP |
| [Illegal Access To User Content via PowerSploit modules](/endpoint/illegal_access_to_user_content_via_powersploit_modules/) | None | TTP |
| [Illegal Privilege Elevation and Persistence via PowerSploit modules](/endpoint/illegal_privilege_elevation_and_persistence_via_powersploit_modules/) | None | TTP |
| [Illegal Service and Process Control via PowerSploit modules](/endpoint/illegal_service_and_process_control_via_powersploit_modules/) | None | TTP |
| [Malicious PowerShell Process - Connect To Internet With Hidden Window](/endpoint/malicious_powershell_process_-_connect_to_internet_with_hidden_window/) | None | TTP |
| [Malicious PowerShell Process - Encoded Command](/endpoint/malicious_powershell_process_-_encoded_command/) | None | Hunting |
| [Malicious PowerShell Process With Obfuscation Techniques](/endpoint/malicious_powershell_process_with_obfuscation_techniques/) | None | TTP |
| [PowerShell 4104 Hunting](/endpoint/powershell_4104_hunting/) | None | Hunting |
| [PowerShell Domain Enumeration](/endpoint/powershell_domain_enumeration/) | None | TTP |
| [PowerShell Loading DotNET into Memory via System Reflection Assembly](/endpoint/powershell_loading_dotnet_into_memory_via_system_reflection_assembly/) | None | TTP |
| [Powershell Creating Thread Mutex](/endpoint/powershell_creating_thread_mutex/) | None | TTP |
| [Powershell Enable SMB1Protocol Feature](/endpoint/powershell_enable_smb1protocol_feature/) | None | TTP |
| [Powershell Execute COM Object](/endpoint/powershell_execute_com_object/) | None | TTP |
| [Powershell Fileless Process Injection via GetProcAddress](/endpoint/powershell_fileless_process_injection_via_getprocaddress/) | None | TTP |
| [Powershell Fileless Script Contains Base64 Encoded Content](/endpoint/powershell_fileless_script_contains_base64_encoded_content/) | None | TTP |
| [Powershell Processing Stream Of Data](/endpoint/powershell_processing_stream_of_data/) | None | TTP |
| [Powershell Using memory As Backing Store](/endpoint/powershell_using_memory_as_backing_store/) | None | TTP |
| [Recon AVProduct Through Pwh or WMI](/endpoint/recon_avproduct_through_pwh_or_wmi/) | None | TTP |
| [Recon Using WMI Class](/endpoint/recon_using_wmi_class/) | None | TTP |
| [Set Default PowerShell Execution Policy To Unrestricted or Bypass](/endpoint/set_default_powershell_execution_policy_to_unrestricted_or_bypass/) | None | TTP |
| [Unloading AMSI via Reflection](/endpoint/unloading_amsi_via_reflection/) | None | TTP |
| [WMI Recon Running Process Or Services](/endpoint/wmi_recon_running_process_or_services/) | None | TTP |

#### Reference

* [https://blogs.mcafee.com/mcafee-labs/malware-employs-powershell-to-infect-systems/](https://blogs.mcafee.com/mcafee-labs/malware-employs-powershell-to-infect-systems/)
* [https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/malicious_powershell.yml) | _version_: **5**