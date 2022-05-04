---
title: "Industroyer2"
last_modified_at: 2022-04-21
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Industroyer2 attack, including file writes associated with its payload, lateral movement, persistence, privilege escalation and data destruction.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7ff7db2b-b001-498e-8fe8-caf2dbc3428a

#### Narrative

Industroyer2 is part of continuous attack to ukraine targeting energy facilities. This malware is a windows binary that implement IEC-104 protocol to communicate with industrial equipments. This attack consist of several destructive linux script component to wipe or delete several linux critical files, powershell for domain enumeration and caddywiper to wipe boot sector of the targeted host.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AdsiSearcher Account Discovery](/endpoint/adsisearcher_account_discovery/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/attempted_credential_dump_from_registry_via_reg_exe/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Dump LSASS via comsvcs DLL](/endpoint/dump_lsass_via_comsvcs_dll/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Executable File Written in Administrative SMB Share](/endpoint/executable_file_written_in_administrative_smb_share/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | [Masquerading](/tags/#masquerading)| TTP |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/impacket_lateral_movement_commandline_parameters/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service)| TTP |
| [Linux DD File Overwrite](/endpoint/linux_dd_file_overwrite/) | [Data Destruction](/tags/#data-destruction)| TTP |
| [Linux System Network Discovery](/endpoint/linux_system_network_discovery/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery)| Anomaly |
| [Schtasks Run Task On Demand](/endpoint/schtasks_run_task_on_demand/) | [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Suspicious Process File Path](/endpoint/suspicious_process_file_path/) | [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/winevent_windows_task_scheduler_event_action_started/) | [Scheduled Task](/tags/#scheduled-task)| Hunting |
| [Linux Stdout Redirection To Dev Null File](/endpoint/linux_stdout_redirection_to_dev_null_file/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses)| Anomaly |

#### Reference

* [https://cert.gov.ua/article/39518](https://cert.gov.ua/article/39518)
* [https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/](https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/industroyer2.yml) \| *version*: **1**