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
  - Actions on Objectives
  - Delivery
  - Exploitation
  - Reconnaissance
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
| [Reg exe used to hide files directories via registry keys](/deprecated/reg_exe_used_to_hide_files_directories_via_registry_keys/) | None| TTP |
| [Remote Registry Key modifications](/deprecated/remote_registry_key_modifications/) | None| TTP |
| [Add or Set Windows Defender Exclusion](/endpoint/add_or_set_windows_defender_exclusion/) | None| TTP |
| [CSC Net On The Fly Compilation](/endpoint/csc_net_on_the_fly_compilation/) | None| Hunting |
| [Disable Registry Tool](/endpoint/disable_registry_tool/) | None| TTP |
| [Disable Security Logs Using MiniNt Registry](/endpoint/disable_security_logs_using_minint_registry/) | None| TTP |
| [Disable Show Hidden Files](/endpoint/disable_show_hidden_files/) | None| TTP |
| [Disable UAC Remote Restriction](/endpoint/disable_uac_remote_restriction/) | None| TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | None| TTP |
| [Disable Windows SmartScreen Protection](/endpoint/disable_windows_smartscreen_protection/) | None| TTP |
| [Disabling CMD Application](/endpoint/disabling_cmd_application/) | None| TTP |
| [Disabling ControlPanel](/endpoint/disabling_controlpanel/) | None| TTP |
| [Disabling Firewall with Netsh](/endpoint/disabling_firewall_with_netsh/) | None| TTP |
| [Disabling FolderOptions Windows Feature](/endpoint/disabling_folderoptions_windows_feature/) | None| TTP |
| [Disabling NoRun Windows App](/endpoint/disabling_norun_windows_app/) | None| TTP |
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | None| TTP |
| [Disabling SystemRestore In Registry](/endpoint/disabling_systemrestore_in_registry/) | None| TTP |
| [Disabling Task Manager](/endpoint/disabling_task_manager/) | None| TTP |
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | None| TTP |
| [Excessive number of service control start as disabled](/endpoint/excessive_number_of_service_control_start_as_disabled/) | None| Anomaly |
| [Firewall Allowed Program Enable](/endpoint/firewall_allowed_program_enable/) | None| Anomaly |
| [FodHelper UAC Bypass](/endpoint/fodhelper_uac_bypass/) | None| TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | None| TTP |
| [NET Profiler UAC bypass](/endpoint/net_profiler_uac_bypass/) | None| TTP |
| [Powershell Windows Defender Exclusion Commands](/endpoint/powershell_windows_defender_exclusion_commands/) | None| TTP |
| [Sdclt UAC Bypass](/endpoint/sdclt_uac_bypass/) | None| TTP |
| [SilentCleanup UAC Bypass](/endpoint/silentcleanup_uac_bypass/) | None| TTP |
| [SLUI RunAs Elevated](/endpoint/slui_runas_elevated/) | None| TTP |
| [SLUI Spawning a Process](/endpoint/slui_spawning_a_process/) | None| TTP |
| [Suspicious Reg exe Process](/endpoint/suspicious_reg_exe_process/) | None| TTP |
| [UAC Bypass MMC Load Unsigned Dll](/endpoint/uac_bypass_mmc_load_unsigned_dll/) | None| TTP |
| [Windows Defender Exclusion Registry Entry](/endpoint/windows_defender_exclusion_registry_entry/) | None| TTP |
| [Windows DisableAntiSpyware Registry](/endpoint/windows_disableantispyware_registry/) | None| TTP |
| [Windows DISM Remove Defender](/endpoint/windows_dism_remove_defender/) | None| TTP |
| [Windows Event For Service Disabled](/endpoint/windows_event_for_service_disabled/) | None| Hunting |
| [Windows Excessive Disabled Services Event](/endpoint/windows_excessive_disabled_services_event/) | None| TTP |
| [Windows Modify Show Compress Color And Info Tip Registry](/endpoint/windows_modify_show_compress_color_and_info_tip_registry/) | None| TTP |
| [Windows Process With NamedPipe CommandLine](/endpoint/windows_process_with_namedpipe_commandline/) | None| Anomaly |
| [Windows Rasautou DLL Execution](/endpoint/windows_rasautou_dll_execution/) | None| TTP |
| [WSReset UAC Bypass](/endpoint/wsreset_uac_bypass/) | None| TTP |

#### Reference

* [https://attack.mitre.org/wiki/Defense_Evasion](https://attack.mitre.org/wiki/Defense_Evasion)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_defense_evasion_tactics.yml) \| *version*: **1**