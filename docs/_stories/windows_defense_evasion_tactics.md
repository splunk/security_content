---
title: "Windows Defense Evasion Tactics"
last_modified_at: 2018-05-31
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

Detect tactics used by malware to evade defenses on Windows endpoints. A few of these include suspicious `reg.exe` processes, files hidden with `attrib.exe` and disabling user-account control, among many others 

- **ID**: 56e24a28-5003-4047-b2db-e8f3c4618064
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: David Dorsey, Splunk

#### Narrative

Defense evasion is a tactic--identified in the MITRE ATT&CK framework--that adversaries employ in a variety of ways to bypass or defeat defensive security measures. There are many techniques enumerated by the MITRE ATT&CK framework that are applicable in this context. This Analytic Story includes searches designed to identify the use of such techniques on Windows platforms.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Disable Registry Tool](/endpoint/disable_registry_tool/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Hidden Files and Directories](/tags/#hidden-files-and-directories), [Bypass User Account Control](/tags/#bypass-user-account-control), [Modify Registry](/tags/#modify-registry), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification), [Masquerading](/tags/#masquerading) | TTP |
| [Disable Show Hidden Files](/endpoint/disable_show_hidden_files/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories), [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disable Windows SmartScreen Protection](/endpoint/disable_windows_smartscreen_protection/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disabling CMD Application](/endpoint/disabling_cmd_application/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disabling ControlPanel](/endpoint/disabling_controlpanel/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disabling Firewall with Netsh](/endpoint/disabling_firewall_with_netsh/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disabling FolderOptions Windows Feature](/endpoint/disabling_folderoptions_windows_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disabling NoRun Windows App](/endpoint/disabling_norun_windows_app/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Port Monitors](/tags/#port-monitors), [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Application Shimming](/tags/#application-shimming) | TTP |
| [Disabling SystemRestore In Registry](/endpoint/disabling_systemrestore_in_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Disabling Task Manager](/endpoint/disabling_task_manager/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control) | TTP |
| [Excessive number of service control start as disabled](/endpoint/excessive_number_of_service_control_start_as_disabled/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | Anomaly |
| [FodHelper UAC Bypass](/endpoint/fodhelper_uac_bypass/) | [Modify Registry](/tags/#modify-registry), [Bypass User Account Control](/tags/#bypass-user-account-control) | TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification) | TTP |
| [NET Profiler UAC bypass](/endpoint/net_profiler_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control) | TTP |
| [SLUI RunAs Elevated](/endpoint/slui_runas_elevated/) | [Bypass User Account Control](/tags/#bypass-user-account-control) | TTP |
| [SLUI Spawning a Process](/endpoint/slui_spawning_a_process/) | [Bypass User Account Control](/tags/#bypass-user-account-control) | TTP |
| [Sdclt UAC Bypass](/endpoint/sdclt_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control) | TTP |
| [SilentCleanup UAC Bypass](/endpoint/silentcleanup_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control) | TTP |
| [Suspicious Reg exe Process](/endpoint/suspicious_reg_exe_process/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [System Process Running from Unexpected Location](/endpoint/system_process_running_from_unexpected_location/) | [Masquerading](/tags/#masquerading) | Anomaly |
| [UAC Bypass MMC Load Unsigned Dll](/endpoint/uac_bypass_mmc_load_unsigned_dll/) | [Bypass User Account Control](/tags/#bypass-user-account-control) | TTP |
| [WSReset UAC Bypass](/endpoint/wsreset_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control) | TTP |
| [Windows DisableAntiSpyware Registry](/endpoint/windows_disableantispyware_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | TTP |

#### Reference

* [https://attack.mitre.org/wiki/Defense_Evasion](https://attack.mitre.org/wiki/Defense_Evasion)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_defense_evasion_tactics.yml) \| *version*: **1**