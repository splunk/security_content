---
title: "Windows Defense Evasion Tactics"
last_modified_at: 2018-05-31
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect tactics used by malware to evade defenses on Windows endpoints. A few of these include suspicious `reg.exe` processes, files hidden with `attrib.exe` and disabling user-account control, among many others 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: David Dorsey, Splunk
- **ID**: 56e24a28-5003-4047-b2db-e8f3c4618064

#### Narrative

Defense evasion is a tactic--identified in the MITRE ATT&CK framework--that adversaries employ in a variety of ways to bypass or defeat defensive security measures. There are many techniques enumerated by the MITRE ATT&CK framework that are applicable in this context. This Analytic Story includes searches designed to identify the use of such techniques on Windows platforms.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Disable Registry Tool](/endpoint/disable_registry_tool/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Security Logs Using MiniNt Registry](/endpoint/disable_security_logs_using_minint_registry/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [Disable Show Hidden Files](/endpoint/disable_show_hidden_files/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Hide Artifacts](/tags/#hide-artifacts), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable UAC Remote Restriction](/endpoint/disable_uac_remote_restriction/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disable Windows SmartScreen Protection](/endpoint/disable_windows_smartscreen_protection/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling CMD Application](/endpoint/disabling_cmd_application/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling ControlPanel](/endpoint/disabling_controlpanel/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling Firewall with Netsh](/endpoint/disabling_firewall_with_netsh/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling FolderOptions Windows Feature](/endpoint/disabling_folderoptions_windows_feature/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling NoRun Windows App](/endpoint/disabling_norun_windows_app/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Disabling SystemRestore In Registry](/endpoint/disabling_systemrestore_in_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Disabling Task Manager](/endpoint/disabling_task_manager/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Excessive number of service control start as disabled](/endpoint/excessive_number_of_service_control_start_as_disabled/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | Anomaly |
| [FodHelper UAC Bypass](/endpoint/fodhelper_uac_bypass/) | [Modify Registry](/tags/#modify-registry), [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification) | TTP |
| [NET Profiler UAC bypass](/endpoint/net_profiler_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [SLUI RunAs Elevated](/endpoint/slui_runas_elevated/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [SLUI Spawning a Process](/endpoint/slui_spawning_a_process/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Sdclt UAC Bypass](/endpoint/sdclt_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [SilentCleanup UAC Bypass](/endpoint/silentcleanup_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Suspicious Reg exe Process](/endpoint/suspicious_reg_exe_process/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [System Process Running from Unexpected Location](/endpoint/system_process_running_from_unexpected_location/) | [Masquerading](/tags/#masquerading) | Anomaly |
| [UAC Bypass MMC Load Unsigned Dll](/endpoint/uac_bypass_mmc_load_unsigned_dll/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [WSReset UAC Bypass](/endpoint/wsreset_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Windows DisableAntiSpyware Registry](/endpoint/windows_disableantispyware_registry/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | TTP |

#### Reference

* [https://attack.mitre.org/wiki/Defense_Evasion](https://attack.mitre.org/wiki/Defense_Evasion)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_defense_evasion_tactics.yml) \| *version*: **1**