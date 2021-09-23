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

[Try in Splunk Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

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
| [7zip CommandLine To SMB Share Path](/endpoint/7zip_commandline_to_smb_share_path/) | [Archive via Utility](/tags/#archive-via-utility), [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism), [Service Stop](/tags/#service-stop), [Inhibit System Recovery](/tags/#inhibit-system-recovery), [CMSTP](/tags/#cmstp), [File Deletion](/tags/#file-deletion), [Data Destruction](/tags/#data-destruction), [User Execution](/tags/#user-execution), [Automated Exfiltration](/tags/#automated-exfiltration), [Domain Account](/tags/#domain-account), [Local Account](/tags/#local-account), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Domain Groups](/tags/#domain-groups), [Local Groups](/tags/#local-groups), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Clear Windows Event Logs](/tags/#clear-windows-event-logs), [Account Access Removal](/tags/#account-access-removal), [Service Execution](/tags/#service-execution), [Visual Basic](/tags/#visual-basic), [Indicator Removal on Host](/tags/#indicator-removal-on-host), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [Defacement](/tags/#defacement), [DLL Side-Loading](/tags/#dll-side-loading), [Indicator Removal from Tools](/tags/#indicator-removal-from-tools), [Component Object Model Hijacking](/tags/#component-object-model-hijacking), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol), [Gather Victim Host Information](/tags/#gather-victim-host-information), [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Modify Registry](/tags/#modify-registry), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Scheduled Task](/tags/#scheduled-task), [Rename System Utilities](/tags/#rename-system-utilities), [Web Protocols](/tags/#web-protocols), [Msiexec](/tags/#msiexec) | Hunting |
| [Allow File And Printing Sharing In Firewall](/endpoint/allow_file_and_printing_sharing_in_firewall/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall) | TTP |
| [Allow Network Discovery In Firewall](/endpoint/allow_network_discovery_in_firewall/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Inhibit System Recovery](/tags/#inhibit-system-recovery), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Defacement](/tags/#defacement), [DLL Side-Loading](/tags/#dll-side-loading), [User Execution](/tags/#user-execution), [Modify Registry](/tags/#modify-registry), [CMSTP](/tags/#cmstp) | TTP |
| [Allow Operation with Consent Admin](/endpoint/allow_operation_with_consent_admin/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Attempt To Disable Services](/endpoint/attempt_to_disable_services/) | [Service Stop](/tags/#service-stop) | TTP |
| [Attempt To delete Services](/endpoint/attempt_to_delete_services/) | [Service Stop](/tags/#service-stop) | TTP |
| [BCDEdit Failure Recovery Modification](/endpoint/bcdedit_failure_recovery_modification/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery), [Data Destruction](/tags/#data-destruction), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Data Encrypted for Impact](/tags/#data-encrypted-for-impact), [Windows Command Shell](/tags/#windows-command-shell), [Scheduled Task](/tags/#scheduled-task), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Service Stop](/tags/#service-stop) | TTP |
| [CMLUA Or CMSTPLUA UAC Bypass](/endpoint/cmlua_or_cmstplua_uac_bypass/) | [CMSTP](/tags/#cmstp) | TTP |
| [Clear Unallocated Sector Using Cipher App](/endpoint/clear_unallocated_sector_using_cipher_app/) | [File Deletion](/tags/#file-deletion) | TTP |
| [Common Ransomware Extensions](/endpoint/common_ransomware_extensions/) | [Data Destruction](/tags/#data-destruction) | Hunting |
| [Common Ransomware Notes](/endpoint/common_ransomware_notes/) | [Data Destruction](/tags/#data-destruction) | Hunting |
| [Conti Common Exec parameter](/endpoint/conti_common_exec_parameter/) | [User Execution](/tags/#user-execution) | TTP |
| [Delete A Net User](/endpoint/delete_a_net_user/) | [Service Stop](/tags/#service-stop) | Anomaly |
| [Delete ShadowCopy With PowerShell](/endpoint/delete_shadowcopy_with_powershell/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Deleting Shadow Copies](/endpoint/deleting_shadow_copies/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery), [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Detect RClone Command-Line Usage](/endpoint/detect_rclone_command-line_usage/) | [Automated Exfiltration](/tags/#automated-exfiltration) | TTP |
| [Detect Renamed RClone](/endpoint/detect_renamed_rclone/) | [Automated Exfiltration](/tags/#automated-exfiltration) | TTP |
| [Detect SharpHound Command-Line Arguments](/endpoint/detect_sharphound_command-line_arguments/) | [Domain Account](/tags/#domain-account), [Local Account](/tags/#local-account), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Domain Groups](/tags/#domain-groups), [Local Groups](/tags/#local-groups) | TTP |
| [Detect SharpHound File Modifications](/endpoint/detect_sharphound_file_modifications/) | [Domain Account](/tags/#domain-account), [Local Account](/tags/#local-account), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Domain Groups](/tags/#domain-groups), [Local Groups](/tags/#local-groups) | TTP |
| [Detect SharpHound Usage](/endpoint/detect_sharphound_usage/) | [Domain Account](/tags/#domain-account), [Local Account](/tags/#local-account), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Domain Groups](/tags/#domain-groups), [Local Groups](/tags/#local-groups) | TTP |
| [Disable AMSI Through Registry](/endpoint/disable_amsi_through_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disable ETW Through Registry](/endpoint/disable_etw_through_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disable Logs Using WevtUtil](/endpoint/disable_logs_using_wevtutil/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Disable Net User Account](/endpoint/disable_net_user_account/) | [Service Stop](/tags/#service-stop) | TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Excessive Service Stop Attempt](/endpoint/excessive_service_stop_attempt/) | [Service Stop](/tags/#service-stop) | Anomaly |
| [Excessive Usage Of Net App](/endpoint/excessive_usage_of_net_app/) | [Account Access Removal](/tags/#account-access-removal) | Anomaly |
| [Excessive Usage Of SC Service Utility](/endpoint/excessive_usage_of_sc_service_utility/) | [Service Execution](/tags/#service-execution) | Anomaly |
| [Execute Javascript With Jscript COM CLSID](/endpoint/execute_javascript_with_jscript_com_clsid/) | [Visual Basic](/tags/#visual-basic) | TTP |
| [Fsutil Zeroing File](/endpoint/fsutil_zeroing_file/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [ICACLS Grant Command](/endpoint/icacls_grant_command/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | TTP |
| [Known Services Killed by Ransomware](/endpoint/known_services_killed_by_ransomware/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Modification Of Wallpaper](/endpoint/modification_of_wallpaper/) | [Defacement](/tags/#defacement) | TTP |
| [Msmpeng Application DLL Side Loading](/endpoint/msmpeng_application_dll_side_loading/) | [DLL Side-Loading](/tags/#dll-side-loading) | TTP |
| [Permission Modification using Takeown App](/endpoint/permission_modification_using_takeown_app/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | TTP |
| [Powershell Disable Security Monitoring](/endpoint/powershell_disable_security_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Powershell Enable SMB1Protocol Feature](/endpoint/powershell_enable_smb1protocol_feature/) | [Indicator Removal from Tools](/tags/#indicator-removal-from-tools) | TTP |
| [Powershell Execute COM Object](/endpoint/powershell_execute_com_object/) | [Component Object Model Hijacking](/tags/#component-object-model-hijacking) | TTP |
| [Prevent Automatic Repair Mode using Bcdedit](/endpoint/prevent_automatic_repair_mode_using_bcdedit/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Prohibited Network Traffic Allowed](/network/prohibited_network_traffic_allowed/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | TTP |
| [Recon AVProduct Through Pwh or WMI](/endpoint/recon_avproduct_through_pwh_or_wmi/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | TTP |
| [Recursive Delete of Directory In Batch CMD](/endpoint/recursive_delete_of_directory_in_batch_cmd/) | [File Deletion](/tags/#file-deletion) | TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder) | TTP |
| [Remote Process Instantiation via WMI](/endpoint/remote_process_instantiation_via_wmi/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | TTP |
| [Resize Shadowstorage Volume](/endpoint/resize_shadowstorage_volume/) | [Service Stop](/tags/#service-stop) | TTP |
| [Revil Common Exec Parameter](/endpoint/revil_common_exec_parameter/) | [User Execution](/tags/#user-execution) | TTP |
| [Revil Registry Entry](/endpoint/revil_registry_entry/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [SMB Traffic Spike](/network/smb_traffic_spike/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | Anomaly |
| [SMB Traffic Spike - MLTK](/network/smb_traffic_spike_-_mltk/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | Anomaly |
| [Schtasks used for forcing a reboot](/endpoint/schtasks_used_for_forcing_a_reboot/) | [Scheduled Task](/tags/#scheduled-task) | TTP |
| [Spike in File Writes](/endpoint/spike_in_file_writes/) |  | Anomaly |
| [Start Up During Safe Mode Boot](/endpoint/start_up_during_safe_mode_boot/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder) | TTP |
| [Suspicious Event Log Service Behavior](/endpoint/suspicious_event_log_service_behavior/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | [Scheduled Task](/tags/#scheduled-task) | Anomaly |
| [Suspicious wevtutil Usage](/endpoint/suspicious_wevtutil_usage/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | [Rename System Utilities](/tags/#rename-system-utilities) | TTP |
| [TOR Traffic](/network/tor_traffic/) | [Web Protocols](/tags/#web-protocols) | TTP |
| [UAC Bypass With Colorui COM Object](/endpoint/uac_bypass_with_colorui_com_object/) | [CMSTP](/tags/#cmstp) | TTP |
| [USN Journal Deletion](/endpoint/usn_journal_deletion/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [Uninstall App Using MsiExec](/endpoint/uninstall_app_using_msiexec/) | [Msiexec](/tags/#msiexec) | TTP |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) |  | Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) |  | Anomaly |
| [WBAdmin Delete System Backups](/endpoint/wbadmin_delete_system_backups/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Wbemprox COM Object Execution](/endpoint/wbemprox_com_object_execution/) | [CMSTP](/tags/#cmstp) | TTP |
| [WevtUtil Usage To Clear Logs](/endpoint/wevtutil_usage_to_clear_logs/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Wevtutil Usage To Disable Logs](/endpoint/wevtutil_usage_to_disable_logs/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | [Scheduled Task](/tags/#scheduled-task) | TTP |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/winevent_scheduled_task_created_to_spawn_shell/) | [Scheduled Task](/tags/#scheduled-task) | TTP |
| [Windows Event Log Cleared](/endpoint/windows_event_log_cleared/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |

#### Reference

* [https://www.carbonblack.com/2017/06/28/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware/](https://www.carbonblack.com/2017/06/28/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware/)
* [https://www.splunk.com/blog/2017/06/27/closing-the-detection-to-mitigation-gap-or-to-petya-or-notpetya-whocares-.html](https://www.splunk.com/blog/2017/06/27/closing-the-detection-to-mitigation-gap-or-to-petya-or-notpetya-whocares-.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ransomware.yml) \| *version*: **1**