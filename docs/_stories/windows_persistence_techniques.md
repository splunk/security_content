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
| [Reg exe used to hide files directories via registry keys](/deprecated/reg_exe_used_to_hide_files_directories_via_registry_keys/) | None| TTP |
| [Remote Registry Key modifications](/deprecated/remote_registry_key_modifications/) | None| TTP |
| [Active Setup Registry Autostart](/endpoint/active_setup_registry_autostart/) | None| TTP |
| [Certutil exe certificate extraction](/endpoint/certutil_exe_certificate_extraction/) | None| TTP |
| [Change Default File Association](/endpoint/change_default_file_association/) | None| TTP |
| [Detect Path Interception By Creation Of program exe](/endpoint/detect_path_interception_by_creation_of_program_exe/) | None| TTP |
| [ETW Registry Disabled](/endpoint/etw_registry_disabled/) | None| TTP |
| [Hiding Files And Directories With Attrib exe](/endpoint/hiding_files_and_directories_with_attrib_exe/) | None| TTP |
| [Logon Script Event Trigger Execution](/endpoint/logon_script_event_trigger_execution/) | None| TTP |
| [Monitor Registry Keys for Print Monitors](/endpoint/monitor_registry_keys_for_print_monitors/) | None| TTP |
| [Reg exe Manipulating Windows Services Registry Keys](/endpoint/reg_exe_manipulating_windows_services_registry_keys/) | None| TTP |
| [Registry Keys for Creating SHIM Databases](/endpoint/registry_keys_for_creating_shim_databases/) | None| TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | None| TTP |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | None| TTP |
| [Schedule Task with HTTP Command Arguments](/endpoint/schedule_task_with_http_command_arguments/) | None| TTP |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/schedule_task_with_rundll32_command_trigger/) | None| TTP |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/scheduled_task_deleted_or_created_via_cmd/) | None| TTP |
| [Schtasks used for forcing a reboot](/endpoint/schtasks_used_for_forcing_a_reboot/) | None| TTP |
| [Screensaver Event Trigger Execution](/endpoint/screensaver_event_trigger_execution/) | None| TTP |
| [Shim Database File Creation](/endpoint/shim_database_file_creation/) | None| TTP |
| [Shim Database Installation With Suspicious Parameters](/endpoint/shim_database_installation_with_suspicious_parameters/) | None| TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | None| Anomaly |
| [Time Provider Persistence Registry](/endpoint/time_provider_persistence_registry/) | None| TTP |
| [Windows Schtasks Create Run As System](/endpoint/windows_schtasks_create_run_as_system/) | None| TTP |
| [Windows Service Creation Using Registry Entry](/endpoint/windows_service_creation_using_registry_entry/) | None| TTP |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/winevent_scheduled_task_created_to_spawn_shell/) | None| TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | None| TTP |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/winevent_windows_task_scheduler_event_action_started/) | None| Hunting |
| [Print Processor Registry Autostart](/endpoint/print_processor_registry_autostart/) | None| TTP |

#### Reference

* [http://www.fuzzysecurity.com/tutorials/19.html](http://www.fuzzysecurity.com/tutorials/19.html)
* [https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html](https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html)
* [http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/](http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/)
* [https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)
* [https://www.youtube.com/watch?v=dq2Hv7J9fvk](https://www.youtube.com/watch?v=dq2Hv7J9fvk)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_persistence_techniques.yml) \| *version*: **2**