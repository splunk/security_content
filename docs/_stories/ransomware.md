---
title: "Ransomware"
last_modified_at: 2020-02-04
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Actions on Objectives
  - Command & Control
  - Delivery
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to ransomware--spikes in SMB traffic, suspicious wevtutil usage, the presence of common ransomware extensions, and system processes run from unexpected locations, and many others.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-02-04
- **Author**: David Dorsey, Splunk
- **ID**: cf309d0d-d4aa-4fbb-963d-1e79febd3756

#### Narrative

Ransomware is an ever-present risk to the enterprise, wherein an infected host encrypts business-critical data, holding it hostage until the victim pays the attacker a ransom. There are many types and varieties of ransomware that can affect an enterprise. Attackers can deploy ransomware to enterprises through spearphishing campaigns and driveby downloads, as well as through traditional remote service-based exploitation. In the case of the WannaCry campaign, there was self-propagating wormable functionality that was used to maximize infection. Fortunately, organizations can apply several techniques--such as those in this Analytic Story--to detect and or mitigate the effects of ransomware.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Scheduled tasks used in BadRabbit ransomware](/deprecated/scheduled_tasks_used_in_badrabbit_ransomware/) | [Scheduled Task](/tags/#scheduled-task)| TTP |
| [7zip CommandLine To SMB Share Path](/endpoint/7zip_commandline_to_smb_share_path/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data)| Hunting |
| [Allow File And Printing Sharing In Firewall](/endpoint/allow_file_and_printing_sharing_in_firewall/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Allow Network Discovery In Firewall](/endpoint/allow_network_discovery_in_firewall/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Allow Operation with Consent Admin](/endpoint/allow_operation_with_consent_admin/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [BCDEdit Failure Recovery Modification](/endpoint/bcdedit_failure_recovery_modification/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Clear Unallocated Sector Using Cipher App](/endpoint/clear_unallocated_sector_using_cipher_app/) | [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host)| TTP |
| [CMLUA Or CMSTPLUA UAC Bypass](/endpoint/cmlua_or_cmstplua_uac_bypass/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [CMSTP](/tags/#cmstp)| TTP |
| [Common Ransomware Extensions](/endpoint/common_ransomware_extensions/) | [Data Destruction](/tags/#data-destruction)| Hunting |
| [Common Ransomware Notes](/endpoint/common_ransomware_notes/) | [Data Destruction](/tags/#data-destruction)| Hunting |
| [Conti Common Exec parameter](/endpoint/conti_common_exec_parameter/) | [User Execution](/tags/#user-execution)| TTP |
| [Delete ShadowCopy With PowerShell](/endpoint/delete_shadowcopy_with_powershell/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Deleting Shadow Copies](/endpoint/deleting_shadow_copies/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Detect RClone Command-Line Usage](/endpoint/detect_rclone_command-line_usage/) | [Automated Exfiltration](/tags/#automated-exfiltration)| TTP |
| [Detect Renamed RClone](/endpoint/detect_renamed_rclone/) | [Automated Exfiltration](/tags/#automated-exfiltration)| Hunting |
| [Detect SharpHound Command-Line Arguments](/endpoint/detect_sharphound_command-line_arguments/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery)| TTP |
| [Detect SharpHound File Modifications](/endpoint/detect_sharphound_file_modifications/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery)| TTP |
| [Detect SharpHound Usage](/endpoint/detect_sharphound_usage/) | [Domain Account](/tags/#domain-account), [Local Groups](/tags/#local-groups), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Local Account](/tags/#local-account), [Account Discovery](/tags/#account-discovery), [Domain Groups](/tags/#domain-groups), [Permission Groups Discovery](/tags/#permission-groups-discovery)| TTP |
| [Disable AMSI Through Registry](/endpoint/disable_amsi_through_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Disable ETW Through Registry](/endpoint/disable_etw_through_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Disable Logs Using WevtUtil](/endpoint/disable_logs_using_wevtutil/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs)| TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Excessive Service Stop Attempt](/endpoint/excessive_service_stop_attempt/) | [Service Stop](/tags/#service-stop)| Anomaly |
| [Excessive Usage Of Net App](/endpoint/excessive_usage_of_net_app/) | [Account Access Removal](/tags/#account-access-removal)| Anomaly |
| [Excessive Usage Of SC Service Utility](/endpoint/excessive_usage_of_sc_service_utility/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution)| Anomaly |
| [Execute Javascript With Jscript COM CLSID](/endpoint/execute_javascript_with_jscript_com_clsid/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Visual Basic](/tags/#visual-basic)| TTP |
| [Fsutil Zeroing File](/endpoint/fsutil_zeroing_file/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host)| TTP |
| [ICACLS Grant Command](/endpoint/icacls_grant_command/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification)| TTP |
| [Known Services Killed by Ransomware](/endpoint/known_services_killed_by_ransomware/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Modification Of Wallpaper](/endpoint/modification_of_wallpaper/) | [Defacement](/tags/#defacement)| TTP |
| [Msmpeng Application DLL Side Loading](/endpoint/msmpeng_application_dll_side_loading/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow)| TTP |
| [Permission Modification using Takeown App](/endpoint/permission_modification_using_takeown_app/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification)| TTP |
| [Powershell Disable Security Monitoring](/endpoint/powershell_disable_security_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Powershell Enable SMB1Protocol Feature](/endpoint/powershell_enable_smb1protocol_feature/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Indicator Removal from Tools](/tags/#indicator-removal-from-tools)| TTP |
| [Powershell Execute COM Object](/endpoint/powershell_execute_com_object/) | [Component Object Model Hijacking](/tags/#component-object-model-hijacking), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Prevent Automatic Repair Mode using Bcdedit](/endpoint/prevent_automatic_repair_mode_using_bcdedit/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Recon AVProduct Through Pwh or WMI](/endpoint/recon_avproduct_through_pwh_or_wmi/) | [Gather Victim Host Information](/tags/#gather-victim-host-information)| TTP |
| [Recursive Delete of Directory In Batch CMD](/endpoint/recursive_delete_of_directory_in_batch_cmd/) | [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host)| TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Remote Process Instantiation via WMI](/endpoint/remote_process_instantiation_via_wmi/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Revil Common Exec Parameter](/endpoint/revil_common_exec_parameter/) | [User Execution](/tags/#user-execution)| TTP |
| [Revil Registry Entry](/endpoint/revil_registry_entry/) | [Modify Registry](/tags/#modify-registry)| TTP |
| [Schtasks used for forcing a reboot](/endpoint/schtasks_used_for_forcing_a_reboot/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Start Up During Safe Mode Boot](/endpoint/start_up_during_safe_mode_boot/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Suspicious Event Log Service Behavior](/endpoint/suspicious_event_log_service_behavior/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs)| TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Suspicious wevtutil Usage](/endpoint/suspicious_wevtutil_usage/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs), [Indicator Removal on Host](/tags/#indicator-removal-on-host)| TTP |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities)| TTP |
| [UAC Bypass With Colorui COM Object](/endpoint/uac_bypass_with_colorui_com_object/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [CMSTP](/tags/#cmstp)| TTP |
| [Uninstall App Using MsiExec](/endpoint/uninstall_app_using_msiexec/) | [Msiexec](/tags/#msiexec), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution)| TTP |
| [USN Journal Deletion](/endpoint/usn_journal_deletion/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host)| TTP |
| [WBAdmin Delete System Backups](/endpoint/wbadmin_delete_system_backups/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Wbemprox COM Object Execution](/endpoint/wbemprox_com_object_execution/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [CMSTP](/tags/#cmstp)| TTP |
| [Windows Disable Change Password Through Registry](/endpoint/windows_disable_change_password_through_registry/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Disable Lock Workstation Feature Through Registry](/endpoint/windows_disable_lock_workstation_feature_through_registry/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Disable LogOff Button Through Registry](/endpoint/windows_disable_logoff_button_through_registry/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Disable Memory Crash Dump](/endpoint/windows_disable_memory_crash_dump/) | [Data Destruction](/tags/#data-destruction)| TTP |
| [Windows Disable Shutdown Button Through Registry](/endpoint/windows_disable_shutdown_button_through_registry/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Disable Windows Group Policy Features Through Registry](/endpoint/windows_disable_windows_group_policy_features_through_registry/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows DiskCryptor Usage](/endpoint/windows_diskcryptor_usage/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact)| Hunting |
| [Windows DotNet Binary in Non Standard Path](/endpoint/windows_dotnet_binary_in_non_standard_path/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [InstallUtil](/tags/#installutil)| TTP |
| [Windows Event Log Cleared](/endpoint/windows_event_log_cleared/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs)| TTP |
| [Windows Hide Notification Features Through Registry](/endpoint/windows_hide_notification_features_through_registry/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows InstallUtil in Non Standard Path](/endpoint/windows_installutil_in_non_standard_path/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [InstallUtil](/tags/#installutil)| TTP |
| [Windows NirSoft AdvancedRun](/endpoint/windows_nirsoft_advancedrun/) | [Tool](/tags/#tool)| TTP |
| [Windows Raccine Scheduled Task Deletion](/endpoint/windows_raccine_scheduled_task_deletion/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools)| TTP |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/winevent_scheduled_task_created_to_spawn_shell/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [MS Exchange Mailbox Replication service writing Active Server Pages](/endpoint/ms_exchange_mailbox_replication_service_writing_active_server_pages/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |
| [Spike in File Writes](/endpoint/spike_in_file_writes/) | None| Anomaly |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) | None| Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) | None| Anomaly |
| [Prohibited Network Traffic Allowed](/network/prohibited_network_traffic_allowed/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| TTP |
| [SMB Traffic Spike](/network/smb_traffic_spike/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Remote Services](/tags/#remote-services)| Anomaly |
| [SMB Traffic Spike - MLTK](/network/smb_traffic_spike_-_mltk/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Remote Services](/tags/#remote-services)| Anomaly |
| [TOR Traffic](/network/tor_traffic/) | [Application Layer Protocol](/tags/#application-layer-protocol), [Web Protocols](/tags/#web-protocols)| TTP |

#### Reference

* [https://www.carbonblack.com/2017/06/28/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware/](https://www.carbonblack.com/2017/06/28/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware/)
* [https://www.splunk.com/blog/2017/06/27/closing-the-detection-to-mitigation-gap-or-to-petya-or-notpetya-whocares-.html](https://www.splunk.com/blog/2017/06/27/closing-the-detection-to-mitigation-gap-or-to-petya-or-notpetya-whocares-.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ransomware.yml) \| *version*: **1**