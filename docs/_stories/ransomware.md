---
title: "Ransomware"
last_modified_at: 2020-02-04
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to ransomware--spikes in SMB traffic, suspicious wevtutil usage, the presence of common ransomware extensions, and system processes run from unexpected locations, and many others.

- **ID**: cf309d0d-d4aa-4fbb-963d-1e79febd3756
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-02-04
- **Author**: David Dorsey, Splunk

#### Narrative

Ransomware is an ever-present risk to the enterprise, wherein an infected host encrypts business-critical data, holding it hostage until the victim pays the attacker a ransom. There are many types and varieties of ransomware that can affect an enterprise. Attackers can deploy ransomware to enterprises through spearphishing campaigns and driveby downloads, as well as through traditional remote service-based exploitation. In the case of the WannaCry campaign, there was self-propagating wormable functionality that was used to maximize infection. Fortunately, organizations can apply several techniques--such as those in this Analytic Story--to detect and or mitigate the effects of ransomware.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [7zip CommandLine To SMB Share Path](/endpoint/7zip_commandline_to_smb_share_path/) | None | Hunting |
| [Allow File And Printing Sharing In Firewall](/endpoint/allow_file_and_printing_sharing_in_firewall/) | None | TTP |
| [Allow Network Discovery In Firewall](/endpoint/allow_network_discovery_in_firewall/) | None | TTP |
| [Allow Operation with Consent Admin](/endpoint/allow_operation_with_consent_admin/) | None | TTP |
| [Attempt To Disable Services](/endpoint/attempt_to_disable_services/) | None | TTP |
| [Attempt To delete Services](/endpoint/attempt_to_delete_services/) | None | TTP |
| [BCDEdit Failure Recovery Modification](/endpoint/bcdedit_failure_recovery_modification/) | None | TTP |
| [CMLUA Or CMSTPLUA UAC Bypass](/endpoint/cmlua_or_cmstplua_uac_bypass/) | None | TTP |
| [Clear Unallocated Sector Using Cipher App](/endpoint/clear_unallocated_sector_using_cipher_app/) | None | TTP |
| [Common Ransomware Extensions](/endpoint/common_ransomware_extensions/) | None | Hunting |
| [Common Ransomware Notes](/endpoint/common_ransomware_notes/) | None | Hunting |
| [Conti Common Exec parameter](/endpoint/conti_common_exec_parameter/) | None | TTP |
| [Delete A Net User](/endpoint/delete_a_net_user/) | None | Anomaly |
| [Delete ShadowCopy With PowerShell](/endpoint/delete_shadowcopy_with_powershell/) | None | TTP |
| [Deleting Shadow Copies](/endpoint/deleting_shadow_copies/) | None | TTP |
| [Detect RClone Command-Line Usage](/endpoint/detect_rclone_command-line_usage/) | None | TTP |
| [Detect Renamed RClone](/endpoint/detect_renamed_rclone/) | None | TTP |
| [Detect SharpHound Command-Line Arguments](/endpoint/detect_sharphound_command-line_arguments/) | None | TTP |
| [Detect SharpHound File Modifications](/endpoint/detect_sharphound_file_modifications/) | None | TTP |
| [Detect SharpHound Usage](/endpoint/detect_sharphound_usage/) | None | TTP |
| [Disable AMSI Through Registry](/endpoint/disable_amsi_through_registry/) | None | TTP |
| [Disable ETW Through Registry](/endpoint/disable_etw_through_registry/) | None | TTP |
| [Disable Logs Using WevtUtil](/endpoint/disable_logs_using_wevtutil/) | None | TTP |
| [Disable Net User Account](/endpoint/disable_net_user_account/) | None | TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | None | TTP |
| [Excessive Service Stop Attempt](/endpoint/excessive_service_stop_attempt/) | None | Anomaly |
| [Excessive Usage Of Net App](/endpoint/excessive_usage_of_net_app/) | None | Anomaly |
| [Excessive Usage Of SC Service Utility](/endpoint/excessive_usage_of_sc_service_utility/) | None | Anomaly |
| [Execute Javascript With Jscript COM CLSID](/endpoint/execute_javascript_with_jscript_com_clsid/) | None | TTP |
| [Fsutil Zeroing File](/endpoint/fsutil_zeroing_file/) | None | TTP |
| [ICACLS Grant Command](/endpoint/icacls_grant_command/) | None | TTP |
| [Known Services Killed by Ransomware](/endpoint/known_services_killed_by_ransomware/) | None | TTP |
| [Modification Of Wallpaper](/endpoint/modification_of_wallpaper/) | None | TTP |
| [Msmpeng Application DLL Side Loading](/endpoint/msmpeng_application_dll_side_loading/) | None | TTP |
| [Permission Modification using Takeown App](/endpoint/permission_modification_using_takeown_app/) | None | TTP |
| [Powershell Disable Security Monitoring](/endpoint/powershell_disable_security_monitoring/) | None | TTP |
| [Powershell Enable SMB1Protocol Feature](/endpoint/powershell_enable_smb1protocol_feature/) | None | TTP |
| [Powershell Execute COM Object](/endpoint/powershell_execute_com_object/) | None | TTP |
| [Prevent Automatic Repair Mode using Bcdedit](/endpoint/prevent_automatic_repair_mode_using_bcdedit/) | None | TTP |
| [Prohibited Network Traffic Allowed](/network/prohibited_network_traffic_allowed/) | None | TTP |
| [Recon AVProduct Through Pwh or WMI](/endpoint/recon_avproduct_through_pwh_or_wmi/) | None | TTP |
| [Recursive Delete of Directory In Batch CMD](/endpoint/recursive_delete_of_directory_in_batch_cmd/) | None | TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | None | TTP |
| [Remote Process Instantiation via WMI](/endpoint/remote_process_instantiation_via_wmi/) | None | TTP |
| [Resize Shadowstorage Volume](/endpoint/resize_shadowstorage_volume/) | None | TTP |
| [Revil Common Exec Parameter](/endpoint/revil_common_exec_parameter/) | None | TTP |
| [Revil Registry Entry](/endpoint/revil_registry_entry/) | None | TTP |
| [SMB Traffic Spike](/network/smb_traffic_spike/) | None | Anomaly |
| [SMB Traffic Spike - MLTK](/network/smb_traffic_spike_-_mltk/) | None | Anomaly |
| [Schtasks used for forcing a reboot](/endpoint/schtasks_used_for_forcing_a_reboot/) | None | TTP |
| [Spike in File Writes](/endpoint/spike_in_file_writes/) | None | Anomaly |
| [Start Up During Safe Mode Boot](/endpoint/start_up_during_safe_mode_boot/) | None | TTP |
| [Suspicious Event Log Service Behavior](/endpoint/suspicious_event_log_service_behavior/) | None | TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | None | Anomaly |
| [Suspicious wevtutil Usage](/endpoint/suspicious_wevtutil_usage/) | None | TTP |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | None | TTP |
| [TOR Traffic](/network/tor_traffic/) | None | TTP |
| [UAC Bypass With Colorui COM Object](/endpoint/uac_bypass_with_colorui_com_object/) | None | TTP |
| [USN Journal Deletion](/endpoint/usn_journal_deletion/) | None | TTP |
| [Uninstall App Using MsiExec](/endpoint/uninstall_app_using_msiexec/) | None | TTP |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) | None | Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) | None | Anomaly |
| [WBAdmin Delete System Backups](/endpoint/wbadmin_delete_system_backups/) | None | TTP |
| [Wbemprox COM Object Execution](/endpoint/wbemprox_com_object_execution/) | None | TTP |
| [WevtUtil Usage To Clear Logs](/endpoint/wevtutil_usage_to_clear_logs/) | None | TTP |
| [Wevtutil Usage To Disable Logs](/endpoint/wevtutil_usage_to_disable_logs/) | None | TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | None | TTP |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/winevent_scheduled_task_created_to_spawn_shell/) | None | TTP |
| [Windows Event Log Cleared](/endpoint/windows_event_log_cleared/) | None | TTP |

#### Reference

* [https://www.carbonblack.com/2017/06/28/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware/](https://www.carbonblack.com/2017/06/28/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware/)
* [https://www.splunk.com/blog/2017/06/27/closing-the-detection-to-mitigation-gap-or-to-petya-or-notpetya-whocares-.html](https://www.splunk.com/blog/2017/06/27/closing-the-detection-to-mitigation-gap-or-to-petya-or-notpetya-whocares-.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ransomware.yml) \| *version*: **1**