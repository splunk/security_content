---
title: "Hermetic Wiper"
last_modified_at: 2022-03-02
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Email
  - Endpoint
  - Actions on Objectives
  - Command & Control
  - Delivery
  - Exploitation
  - Installation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic story contains detections that allow security analysts to detect and investigate unusual activities that might relate to the destructive malware targeting Ukrainian organizations also known as "Hermetic Wiper". This analytic story looks for abuse of Regsvr32, executables written in administrative SMB Share, suspicious processes, disabling of memory crash dump and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email), [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-02
- **Author**: Teoderick Contreras, Rod Soto, Michael Haag, Splunk
- **ID**: b7511c2e-9a10-11ec-99e3-acde48001122

#### Narrative

Hermetic Wiper is destructive malware operation found by Sentinel One targeting multiple organizations in Ukraine. This malicious payload corrupts Master Boot Records, uses signed drivers and manipulates NTFS attributes for file destruction.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Suspicious Powershell Command-Line Arguments](/deprecated/suspicious_powershell_command-line_arguments/) | [PowerShell](/tags/#powershell)| TTP |
| [Uncommon Processes On Endpoint](/deprecated/uncommon_processes_on_endpoint/) | [Malicious File](/tags/#malicious-file)| Hunting |
| [Active Setup Registry Autostart](/endpoint/active_setup_registry_autostart/) | [Active Setup](/tags/#active-setup), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Any Powershell DownloadFile](/endpoint/any_powershell_downloadfile/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Any Powershell DownloadString](/endpoint/any_powershell_downloadstring/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Change Default File Association](/endpoint/change_default_file_association/) | [Change Default File Association](/tags/#change-default-file-association), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [CMD Carry Out String Command Parameter](/endpoint/cmd_carry_out_string_command_parameter/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Detect Empire with PowerShell Script Block Logging](/endpoint/detect_empire_with_powershell_script_block_logging/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Detect Mimikatz With PowerShell Script Block Logging](/endpoint/detect_mimikatz_with_powershell_script_block_logging/) | [OS Credential Dumping](/tags/#os-credential-dumping), [PowerShell](/tags/#powershell)| TTP |
| [ETW Registry Disabled](/endpoint/etw_registry_disabled/) | [Indicator Blocking](/tags/#indicator-blocking), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Executable File Written in Administrative SMB Share](/endpoint/executable_file_written_in_administrative_smb_share/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | [Masquerading](/tags/#masquerading)| TTP |
| [Kerberoasting spn request with RC4 encryption](/endpoint/kerberoasting_spn_request_with_rc4_encryption/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting)| TTP |
| [Linux Java Spawning Shell](/endpoint/linux_java_spawning_shell/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |
| [Logon Script Event Trigger Execution](/endpoint/logon_script_event_trigger_execution/) | [Boot or Logon Initialization Scripts](/tags/#boot-or-logon-initialization-scripts), [Logon Script (Windows)](/tags/#logon-script-(windows))| TTP |
| [Malicious PowerShell Process - Encoded Command](/endpoint/malicious_powershell_process_-_encoded_command/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information)| Hunting |
| [Malicious PowerShell Process With Obfuscation Techniques](/endpoint/malicious_powershell_process_with_obfuscation_techniques/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [MSI Module Loaded by Non-System Binary](/endpoint/msi_module_loaded_by_non-system_binary/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow)| Hunting |
| [Overwriting Accessibility Binaries](/endpoint/overwriting_accessibility_binaries/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Accessibility Features](/tags/#accessibility-features)| TTP |
| [Possible Lateral Movement PowerShell Spawn](/endpoint/possible_lateral_movement_powershell_spawn/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Remote Management](/tags/#windows-remote-management), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Scheduled Task](/tags/#scheduled-task), [Windows Service](/tags/#windows-service), [PowerShell](/tags/#powershell), [MMC](/tags/#mmc)| TTP |
| [PowerShell 4104 Hunting](/endpoint/powershell_4104_hunting/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| Hunting |
| [PowerShell - Connect To Internet With Hidden Window](/endpoint/powershell_-_connect_to_internet_with_hidden_window/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [PowerShell Domain Enumeration](/endpoint/powershell_domain_enumeration/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Powershell Enable SMB1Protocol Feature](/endpoint/powershell_enable_smb1protocol_feature/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Indicator Removal from Tools](/tags/#indicator-removal-from-tools)| TTP |
| [Powershell Execute COM Object](/endpoint/powershell_execute_com_object/) | [Component Object Model Hijacking](/tags/#component-object-model-hijacking), [Event Triggered Execution](/tags/#event-triggered-execution), [PowerShell](/tags/#powershell)| TTP |
| [Powershell Fileless Process Injection via GetProcAddress](/endpoint/powershell_fileless_process_injection_via_getprocaddress/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Process Injection](/tags/#process-injection), [PowerShell](/tags/#powershell)| TTP |
| [Powershell Fileless Script Contains Base64 Encoded Content](/endpoint/powershell_fileless_script_contains_base64_encoded_content/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [PowerShell](/tags/#powershell)| TTP |
| [PowerShell Loading DotNET into Memory via Reflection](/endpoint/powershell_loading_dotnet_into_memory_via_reflection/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Powershell Processing Stream Of Data](/endpoint/powershell_processing_stream_of_data/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Powershell Using memory As Backing Store](/endpoint/powershell_using_memory_as_backing_store/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| TTP |
| [Recon AVProduct Through Pwh or WMI](/endpoint/recon_avproduct_through_pwh_or_wmi/) | [Gather Victim Host Information](/tags/#gather-victim-host-information)| TTP |
| [Recon Using WMI Class](/endpoint/recon_using_wmi_class/) | [Gather Victim Host Information](/tags/#gather-victim-host-information), [PowerShell](/tags/#powershell)| TTP |
| [Registry Keys Used For Privilege Escalation](/endpoint/registry_keys_used_for_privilege_escalation/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Regsvr32 Silent and Install Param Dll Loading](/endpoint/regsvr32_silent_and_install_param_dll_loading/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| Anomaly |
| [Runas Execution in CommandLine](/endpoint/runas_execution_in_commandline/) | [Access Token Manipulation](/tags/#access-token-manipulation), [Token Impersonation/Theft](/tags/#token-impersonation/theft)| Hunting |
| [Screensaver Event Trigger Execution](/endpoint/screensaver_event_trigger_execution/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Screensaver](/tags/#screensaver)| TTP |
| [Set Default PowerShell Execution Policy To Unrestricted or Bypass](/endpoint/set_default_powershell_execution_policy_to_unrestricted_or_bypass/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Suspicious Process File Path](/endpoint/suspicious_process_file_path/) | [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [Time Provider Persistence Registry](/endpoint/time_provider_persistence_registry/) | [Time Providers](/tags/#time-providers), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Unloading AMSI via Reflection](/endpoint/unloading_amsi_via_reflection/) | [Impair Defenses](/tags/#impair-defenses), [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| TTP |
| [W3WP Spawning Shell](/endpoint/w3wp_spawning_shell/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell)| TTP |
| [Windows Disable Memory Crash Dump](/endpoint/windows_disable_memory_crash_dump/) | [Data Destruction](/tags/#data-destruction)| TTP |
| [Windows File Without Extension In Critical Folder](/endpoint/windows_file_without_extension_in_critical_folder/) | [Data Destruction](/tags/#data-destruction)| TTP |
| [Windows Modify Show Compress Color And Info Tip Registry](/endpoint/windows_modify_show_compress_color_and_info_tip_registry/) | [Modify Registry](/tags/#modify-registry)| TTP |
| [Windows Raw Access To Disk Volume Partition](/endpoint/windows_raw_access_to_disk_volume_partition/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe)| Anomaly |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/windows_raw_access_to_master_boot_record_drive/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe)| TTP |
| [WMI Recon Running Process Or Services](/endpoint/wmi_recon_running_process_or_services/) | [Gather Victim Host Information](/tags/#gather-victim-host-information)| TTP |
| [Email Attachments With Lots Of Spaces](/application/email_attachments_with_lots_of_spaces/) | None| Anomaly |
| [Suspicious Email Attachment Extensions](/application/suspicious_email_attachment_extensions/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing)| Anomaly |
| [Child Processes of Spoolsv exe](/endpoint/child_processes_of_spoolsv_exe/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation)| TTP |
| [Print Processor Registry Autostart](/endpoint/print_processor_registry_autostart/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |

#### Reference

* [https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/](https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/)
* [https://www.cisa.gov/uscert/ncas/alerts/aa22-057a](https://www.cisa.gov/uscert/ncas/alerts/aa22-057a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/hermetic_wiper.yml) \| *version*: **1**