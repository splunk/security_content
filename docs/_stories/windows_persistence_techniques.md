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

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with maintaining persistence on a Windows system--a sign that an adversary may have compromised your environment.

- **ID**: 30874d4f-20a1-488f-85ec-5d52ef74e3f9
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: Bhavin Patel, Splunk

#### Narrative

Maintaining persistence is one of the first steps taken by attackers after the initial compromise. Attackers leverage various custom and built-in tools to ensure survivability and persistent access within a compromised enterprise. This Analytic Story provides searches to help you identify various behaviors used by attackers to maintain persistent access to a Windows environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Certutil exe certificate extraction](/endpoint/certutil_exe_certificate_extraction/) |  | TTP |
| [Detect Path Interception By Creation Of program exe](/endpoint/detect_path_interception_by_creation_of_program_exe/) | [Path Interception by Unquoted Path](/tags/#path-interception-by-unquoted-path), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification), [Establish Accounts](/tags/#establish-accounts), [Valid Accounts](/tags/#valid-accounts), [Account Manipulation](/tags/#account-manipulation), [Rogue Domain Controller](/tags/#rogue-domain-controller), [Domain Policy Modification](/tags/#domain-policy-modification), [Scheduled Task/Job](/tags/#scheduled-task/job), [Access Token Manipulation](/tags/#access-token-manipulation), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism), [Port Monitors](/tags/#port-monitors), [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness), [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Application Shimming](/tags/#application-shimming), [Windows Service](/tags/#windows-service), [Scheduled Task](/tags/#scheduled-task), [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification) | TTP |
| [Illegal Account Creation via PowerSploit modules](/endpoint/illegal_account_creation_via_powersploit_modules/) | [Establish Accounts](/tags/#establish-accounts) | TTP |
| [Illegal Enabling or Disabling of Accounts via DSInternals modules](/endpoint/illegal_enabling_or_disabling_of_accounts_via_dsinternals_modules/) | [Valid Accounts](/tags/#valid-accounts), [Account Manipulation](/tags/#account-manipulation) | TTP |
| [Illegal Management of Active Directory Elements and Policies via DSInternals modules](/endpoint/illegal_management_of_active_directory_elements_and_policies_via_dsinternals_modules/) | [Account Manipulation](/tags/#account-manipulation), [Rogue Domain Controller](/tags/#rogue-domain-controller), [Domain Policy Modification](/tags/#domain-policy-modification) | TTP |
| [Illegal Management of Computers and Active Directory Elements via PowerSploit modules](/endpoint/illegal_management_of_computers_and_active_directory_elements_via_powersploit_modules/) | [Account Manipulation](/tags/#account-manipulation), [Rogue Domain Controller](/tags/#rogue-domain-controller), [Domain Policy Modification](/tags/#domain-policy-modification) | TTP |
| [Illegal Privilege Elevation and Persistence via PowerSploit modules](/endpoint/illegal_privilege_elevation_and_persistence_via_powersploit_modules/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Access Token Manipulation](/tags/#access-token-manipulation), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Monitor Registry Keys for Print Monitors](/endpoint/monitor_registry_keys_for_print_monitors/) | [Port Monitors](/tags/#port-monitors) | TTP |
| [Reg exe Manipulating Windows Services Registry Keys](/endpoint/reg_exe_manipulating_windows_services_registry_keys/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness) | TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder) | TTP |
| [Registry Keys for Creating SHIM Databases](/endpoint/registry_keys_for_creating_shim_databases/) | [Application Shimming](/tags/#application-shimming) | TTP |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | [Windows Service](/tags/#windows-service) | TTP |
| [Schedule Task with HTTP Command Arguments](/endpoint/schedule_task_with_http_command_arguments/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/schedule_task_with_rundll32_command_trigger/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | TTP |
| [Schtasks used for forcing a reboot](/endpoint/schtasks_used_for_forcing_a_reboot/) | [Scheduled Task](/tags/#scheduled-task) | TTP |
| [Setting Credentials via DSInternals modules](/endpoint/setting_credentials_via_dsinternals_modules/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation), [Valid Accounts](/tags/#valid-accounts), [Account Manipulation](/tags/#account-manipulation) | TTP |
| [Setting Credentials via Mimikatz modules](/endpoint/setting_credentials_via_mimikatz_modules/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation), [Valid Accounts](/tags/#valid-accounts), [Account Manipulation](/tags/#account-manipulation) | TTP |
| [Setting Credentials via PowerSploit modules](/endpoint/setting_credentials_via_powersploit_modules/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation), [Valid Accounts](/tags/#valid-accounts), [Account Manipulation](/tags/#account-manipulation) | TTP |
| [Shim Database File Creation](/endpoint/shim_database_file_creation/) | [Application Shimming](/tags/#application-shimming) | TTP |
| [Shim Database Installation With Suspicious Parameters](/endpoint/shim_database_installation_with_suspicious_parameters/) | [Application Shimming](/tags/#application-shimming) | TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | [Scheduled Task](/tags/#scheduled-task) | Anomaly |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | [Scheduled Task](/tags/#scheduled-task) | TTP |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/winevent_scheduled_task_created_to_spawn_shell/) | [Scheduled Task](/tags/#scheduled-task) | TTP |

#### Reference

* [http://www.fuzzysecurity.com/tutorials/19.html](http://www.fuzzysecurity.com/tutorials/19.html)
* [https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html](https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html)
* [http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/](http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/)
* [https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)
* [https://www.youtube.com/watch?v=dq2Hv7J9fvk](https://www.youtube.com/watch?v=dq2Hv7J9fvk)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_persistence_techniques.yml) \| *version*: **2**