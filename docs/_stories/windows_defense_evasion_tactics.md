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

#### Description

Detect tactics used by malware to evade defenses on Windows endpoints. A few of these include suspicious `reg.exe` processes, files hidden with `attrib.exe` and disabling user-account control, among many others 

- **ID**: 56e24a28-5003-4047-b2db-e8f3c4618064
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Disable Registry Tool](/endpoint/disable_registry_tool/) | None | TTP |
| [Disable Show Hidden Files](/endpoint/disable_show_hidden_files/) | None | TTP |
| [Disable Windows Behavior Monitoring](/endpoint/disable_windows_behavior_monitoring/) | None | TTP |
| [Disable Windows SmartScreen Protection](/endpoint/disable_windows_smartscreen_protection/) | None | TTP |
| [Disabling CMD Application](/endpoint/disabling_cmd_application/) | None | TTP |
| [Disabling ControlPanel](/endpoint/disabling_controlpanel/) | None | TTP |
| [Disabling Firewall with Netsh](/endpoint/disabling_firewall_with_netsh/) | None | TTP |
| [Disabling FolderOptions Windows Feature](/endpoint/disabling_folderoptions_windows_feature/) | None | TTP |
| [Disabling NoRun Windows App](/endpoint/disabling_norun_windows_app/) | None | TTP |
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | None | TTP |
| [Disabling SystemRestore In Registry](/endpoint/disabling_systemrestore_in_registry/) | None | TTP |
| [Disabling Task Manager](/endpoint/disabling_task_manager/) | None | TTP |
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | None | TTP |
| [Excessive number of service control start as disabled](/endpoint/excessive_number_of_service_control_start_as_disabled/) | None | Anomaly |
| [FodHelper UAC Bypass](/endpoint/fodhelper_uac_bypass/) | None | TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | None | TTP |
| [NET Profiler UAC bypass](/endpoint/net_profiler_uac_bypass/) | None | TTP |
| [SLUI RunAs Elevated](/endpoint/slui_runas_elevated/) | None | TTP |
| [SLUI Spawning a Process](/endpoint/slui_spawning_a_process/) | None | TTP |
| [Sdclt UAC Bypass](/endpoint/sdclt_uac_bypass/) | None | TTP |
| [SilentCleanup UAC Bypass](/endpoint/silentcleanup_uac_bypass/) | None | TTP |
| [Suspicious Reg exe Process](/endpoint/suspicious_reg_exe_process/) | None | TTP |
| [System Process Running from Unexpected Location](/endpoint/system_process_running_from_unexpected_location/) | None | Anomaly |
| [UAC Bypass MMC Load Unsigned Dll](/endpoint/uac_bypass_mmc_load_unsigned_dll/) | None | TTP |
| [WSReset UAC Bypass](/endpoint/wsreset_uac_bypass/) | None | TTP |
| [Windows DisableAntiSpyware Registry](/endpoint/windows_disableantispyware_registry/) | None | TTP |

#### Reference

* [https://attack.mitre.org/wiki/Defense_Evasion](https://attack.mitre.org/wiki/Defense_Evasion)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/windows_defense_evasion_tactics.yml) | _version_: **1**