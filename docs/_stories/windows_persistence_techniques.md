---
title: "Windows Persistence Techniques"
last_modified_at: 2018-05-31
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with maintaining persistence on a Windows system--a sign that an adversary may have compromised your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: Bhavin Patel, Splunk
- **ID**: 30874d4f-20a1-488f-85ec-5d52ef74e3f9

#### Narrative

Maintaining persistence is one of the first steps taken by attackers after the initial compromise. Attackers leverage various custom and built-in tools to ensure survivability and persistent access within a compromised enterprise. This Analytic Story provides searches to help you identify various behaviors used by attackers to maintain persistent access to a Windows environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Reg exe used to hide files directories via registry keys](/deprecated/reg_exe_used_to_hide_files_directories_via_registry_keys/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories)| TTP |
| [Remote Registry Key modifications](/deprecated/remote_registry_key_modifications/) | None| TTP |
| [Active Setup Registry Autostart](/endpoint/active_setup_registry_autostart/) | [Active Setup](/tags/#active-setup), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Certutil exe certificate extraction](/endpoint/certutil_exe_certificate_extraction/) | None| TTP |
| [Change Default File Association](/endpoint/change_default_file_association/) | [Change Default File Association](/tags/#change-default-file-association), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Detect Path Interception By Creation Of program exe](/endpoint/detect_path_interception_by_creation_of_program_exe/) | [Path Interception by Unquoted Path](/tags/#path-interception-by-unquoted-path), [Hijack Execution Flow](/tags/#hijack-execution-flow)| TTP |
| [ETW Registry Disabled](/endpoint/etw_registry_disabled/) | [Indicator Blocking](/tags/#indicator-blocking), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification)| TTP |
| [Logon Script Event Trigger Execution](/endpoint/logon_script_event_trigger_execution/) | [Boot or Logon Initialization Scripts](/tags/#boot-or-logon-initialization-scripts), [Logon Script (Windows)](/tags/#logon-script-(windows))| TTP |
| [Monitor Registry Keys for Print Monitors](/endpoint/monitor_registry_keys_for_print_monitors/) | [Port Monitors](/tags/#port-monitors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Reg exe Manipulating Windows Services Registry Keys](/endpoint/reg_exe_manipulating_windows_services_registry_keys/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness), [Hijack Execution Flow](/tags/#hijack-execution-flow)| TTP |
| [Registry Keys for Creating SHIM Databases](/endpoint/registry_keys_for_creating_shim_databases/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [Schedule Task with HTTP Command Arguments](/endpoint/schedule_task_with_http_command_arguments/) | [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/schedule_task_with_rundll32_command_trigger/) | [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/scheduled_task_deleted_or_created_via_cmd/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Schtasks used for forcing a reboot](/endpoint/schtasks_used_for_forcing_a_reboot/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Screensaver Event Trigger Execution](/endpoint/screensaver_event_trigger_execution/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Screensaver](/tags/#screensaver)| TTP |
| [Shim Database File Creation](/endpoint/shim_database_file_creation/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Shim Database Installation With Suspicious Parameters](/endpoint/shim_database_installation_with_suspicious_parameters/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Time Provider Persistence Registry](/endpoint/time_provider_persistence_registry/) | [Time Providers](/tags/#time-providers), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Windows Schtasks Create Run As System](/endpoint/windows_schtasks_create_run_as_system/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Windows Service Creation Using Registry Entry](/endpoint/windows_service_creation_using_registry_entry/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness)| TTP |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/winevent_scheduled_task_created_to_spawn_shell/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/winevent_windows_task_scheduler_event_action_started/) | [Scheduled Task](/tags/#scheduled-task)| Hunting |
| [Print Processor Registry Autostart](/endpoint/print_processor_registry_autostart/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |

#### Reference

* [http://www.fuzzysecurity.com/tutorials/19.html](http://www.fuzzysecurity.com/tutorials/19.html)
* [https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html](https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html)
* [http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/](http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/)
* [https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)
* [https://www.youtube.com/watch?v=dq2Hv7J9fvk](https://www.youtube.com/watch?v=dq2Hv7J9fvk)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_persistence_techniques.yml) \| *version*: **2**