---
title: "Azorult"
last_modified_at: 2022-06-09
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Delivery
  - Exploitation
  - Installation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Azorult malware including firewall modification, icacl execution, spawning more process, botnet c2 communication, defense evasion and etc. The AZORULT malware was first discovered in 2016 to be an information stealer that steals browsing history, cookies, ID/passwords, cryptocurrency information and more. It can also be a downloader of other malware. A variant of this malware was able to create a new, hidden administrator account on the machine to set a registry key to establish a Remote Desktop Protocol (RDP) connection. Exploit kits such as Fallout Exploit Kit (EK) and phishing mails with social engineering technique are one of the major infection vectors of the AZORult malware. The current malspam and phishing emails use fake product order requests, invoice documents and payment information requests. This Trojan-Spyware connects to command and control (C&C) servers of attacker to send and receive information.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-09
- **Author**: Teoderick Contreras, Splunk
- **ID**: efed5343-4ac2-42b1-a16d-da2428d0ce94

#### Narrative

Adversaries may use this technique to maximize the impact on the target organization in operations where network wide availability interruption is the goal.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Inbound Traffic By Firewall Rule Registry](/endpoint/allow_inbound_traffic_by_firewall_rule_registry/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services)| TTP |
| [Allow Operation with Consent Admin](/endpoint/allow_operation_with_consent_admin/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [Attempt To Stop Security Service](/endpoint/attempt_to_stop_security_service/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [CHCP Command Execution](/endpoint/chcp_command_execution/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| TTP |
| [CMD Carry Out String Command Parameter](/endpoint/cmd_carry_out_string_command_parameter/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Create local admin accounts using net exe](/endpoint/create_local_admin_accounts_using_net_exe/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account)| TTP |
| [Detect Use of cmd exe to Launch Script Interpreters](/endpoint/detect_use_of_cmd_exe_to_launch_script_interpreters/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell)| TTP |
| [Disable Defender BlockAtFirstSeen Feature](/endpoint/disable_defender_blockatfirstseen_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Disable Defender Enhanced Notification](/endpoint/disable_defender_enhanced_notification/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Disable Defender Spynet Reporting](/endpoint/disable_defender_spynet_reporting/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Disable Defender Submit Samples Consent Feature](/endpoint/disable_defender_submit_samples_consent_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Disable Show Hidden Files](/endpoint/disable_show_hidden_files/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Hide Artifacts](/tags/#hide-artifacts), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [Excessive Attempt To Disable Services](/endpoint/excessive_attempt_to_disable_services/) | [Service Stop](/tags/#service-stop)| Anomaly |
| [Excessive Usage Of Cacls App](/endpoint/excessive_usage_of_cacls_app/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification)| Anomaly |
| [Excessive Usage Of Net App](/endpoint/excessive_usage_of_net_app/) | [Account Access Removal](/tags/#account-access-removal)| Anomaly |
| [Excessive Usage Of SC Service Utility](/endpoint/excessive_usage_of_sc_service_utility/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution)| Anomaly |
| [Excessive Usage Of Taskkill](/endpoint/excessive_usage_of_taskkill/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| Anomaly |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | [Masquerading](/tags/#masquerading)| TTP |
| [Firewall Allowed Program Enable](/endpoint/firewall_allowed_program_enable/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses)| Anomaly |
| [Hide User Account From Sign-In Screen](/endpoint/hide_user_account_from_sign-in_screen/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification)| TTP |
| [Icacls Deny Command](/endpoint/icacls_deny_command/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification)| TTP |
| [Net Localgroup Discovery](/endpoint/net_localgroup_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups)| Hunting |
| [Network Connection Discovery With Net](/endpoint/network_connection_discovery_with_net/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery)| Hunting |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/non_firefox_process_access_firefox_profile_dir/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers)| Anomaly |
| [Processes launching netsh](/endpoint/processes_launching_netsh/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/scheduled_task_deleted_or_created_via_cmd/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Windows Application Layer Protocol RMS Radmin Tool Namedpipe](/endpoint/windows_application_layer_protocol_rms_radmin_tool_namedpipe/) | [Application Layer Protocol](/tags/#application-layer-protocol)| TTP |
| [Windows Defender Exclusion Registry Entry](/endpoint/windows_defender_exclusion_registry_entry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Windows DisableAntiSpyware Registry](/endpoint/windows_disableantispyware_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Windows Gather Victim Network Info Through Ip Check Web Services](/endpoint/windows_gather_victim_network_info_through_ip_check_web_services/) | [IP Addresses](/tags/#ip-addresses), [Gather Victim Network Information](/tags/#gather-victim-network-information)| Hunting |
| [Windows Impair Defense Add Xml Applocker Rules](/endpoint/windows_impair_defense_add_xml_applocker_rules/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| Hunting |
| [Windows Impair Defense Deny Security Software With Applocker](/endpoint/windows_impair_defense_deny_security_software_with_applocker/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Windows Modify Registry Disable Toast Notifications](/endpoint/windows_modify_registry_disable_toast_notifications/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Modify Registry Disable Win Defender Raw Write Notif](/endpoint/windows_modify_registry_disable_win_defender_raw_write_notif/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Modify Registry Disable Windows Security Center Notif](/endpoint/windows_modify_registry_disable_windows_security_center_notif/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Modify Registry Disabling WER Settings](/endpoint/windows_modify_registry_disabling_wer_settings/) | [Modify Registry](/tags/#modify-registry)| TTP |
| [Windows Modify Registry DisAllow Windows App](/endpoint/windows_modify_registry_disallow_windows_app/) | [Modify Registry](/tags/#modify-registry)| TTP |
| [Windows Modify Registry Regedit Silent Reg Import](/endpoint/windows_modify_registry_regedit_silent_reg_import/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Modify Registry Suppress Win Defender Notif](/endpoint/windows_modify_registry_suppress_win_defender_notif/) | [Modify Registry](/tags/#modify-registry)| Anomaly |
| [Windows Powershell Import Applocker Policy](/endpoint/windows_powershell_import_applocker_policy/) | [PowerShell](/tags/#powershell)| TTP |
| [Windows Remote Access Software RMS Registry](/endpoint/windows_remote_access_software_rms_registry/) | [Remote Access Software](/tags/#remote-access-software)| TTP |
| [Windows Remote Service Rdpwinst Tool Execution](/endpoint/windows_remote_service_rdpwinst_tool_execution/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services)| TTP |
| [Windows Remote Services Allow Rdp In Firewall](/endpoint/windows_remote_services_allow_rdp_in_firewall/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services)| Anomaly |
| [Windows Remote Services Allow Remote Assistance](/endpoint/windows_remote_services_allow_remote_assistance/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services)| Anomaly |
| [Windows Remote Services Rdp Enable](/endpoint/windows_remote_services_rdp_enable/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services)| TTP |
| [Windows Service Stop By Deletion](/endpoint/windows_service_stop_by_deletion/) | [Service Stop](/tags/#service-stop)| TTP |
| [Windows Valid Account With Never Expires Password](/endpoint/windows_valid_account_with_never_expires_password/) | [Service Stop](/tags/#service-stop)| TTP |
| [Wmic NonInteractive App Uninstallation](/endpoint/wmic_noninteractive_app_uninstallation/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| Hunting |

#### Reference

* [https://success.trendmicro.com/dcx/s/solution/000146108-azorult-malware-information?language=en_US&sfdcIFrameOrigin=null](https://success.trendmicro.com/dcx/s/solution/000146108-azorult-malware-information?language=en_US&sfdcIFrameOrigin=null)
* [https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/](https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/azorult.yml) \| *version*: **1**