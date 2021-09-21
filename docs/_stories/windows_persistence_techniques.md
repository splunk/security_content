---
title: "Windows Persistence Techniques"
last_modified_at: 2018-05-31
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor for activities and techniques associated with maintaining persistence on a Windows system--a sign that an adversary may have compromised your environment.

- **ID**: 30874d4f-20a1-488f-85ec-5d52ef74e3f9
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Certutil exe certificate extraction](/endpoint/certutil_exe_certificate_extraction/) | None | TTP |
| [Detect Path Interception By Creation Of program exe](/endpoint/detect_path_interception_by_creation_of_program_exe/) | None | TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | None | TTP |
| [Illegal Account Creation via PowerSploit modules](/endpoint/illegal_account_creation_via_powersploit_modules/) | None | TTP |
| [Illegal Enabling or Disabling of Accounts via DSInternals modules](/endpoint/illegal_enabling_or_disabling_of_accounts_via_dsinternals_modules/) | None | TTP |
| [Illegal Management of Active Directory Elements and Policies via DSInternals modules](/endpoint/illegal_management_of_active_directory_elements_and_policies_via_dsinternals_modules/) | None | TTP |
| [Illegal Management of Computers and Active Directory Elements via PowerSploit modules](/endpoint/illegal_management_of_computers_and_active_directory_elements_via_powersploit_modules/) | None | TTP |
| [Illegal Privilege Elevation and Persistence via PowerSploit modules](/endpoint/illegal_privilege_elevation_and_persistence_via_powersploit_modules/) | None | TTP |
| [Monitor Registry Keys for Print Monitors](/endpoint/monitor_registry_keys_for_print_monitors/) | None | TTP |
| [Reg exe Manipulating Windows Services Registry Keys](/endpoint/reg_exe_manipulating_windows_services_registry_keys/) | None | TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | None | TTP |
| [Registry Keys for Creating SHIM Databases](/endpoint/registry_keys_for_creating_shim_databases/) | None | TTP |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | None | TTP |
| [Schedule Task with HTTP Command Arguments](/endpoint/schedule_task_with_http_command_arguments/) | None | TTP |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/schedule_task_with_rundll32_command_trigger/) | None | TTP |
| [Schtasks used for forcing a reboot](/endpoint/schtasks_used_for_forcing_a_reboot/) | None | TTP |
| [Setting Credentials via DSInternals modules](/endpoint/setting_credentials_via_dsinternals_modules/) | None | TTP |
| [Setting Credentials via Mimikatz modules](/endpoint/setting_credentials_via_mimikatz_modules/) | None | TTP |
| [Setting Credentials via PowerSploit modules](/endpoint/setting_credentials_via_powersploit_modules/) | None | TTP |
| [Shim Database File Creation](/endpoint/shim_database_file_creation/) | None | TTP |
| [Shim Database Installation With Suspicious Parameters](/endpoint/shim_database_installation_with_suspicious_parameters/) | None | TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | None | Anomaly |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | None | TTP |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/winevent_scheduled_task_created_to_spawn_shell/) | None | TTP |

#### Reference

* [http://www.fuzzysecurity.com/tutorials/19.html](http://www.fuzzysecurity.com/tutorials/19.html)
* [https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html](https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html)
* [http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/](http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/)
* [https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)
* [https://www.youtube.com/watch?v=dq2Hv7J9fvk](https://www.youtube.com/watch?v=dq2Hv7J9fvk)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_persistence_techniques.yml) \| *version*: **2**