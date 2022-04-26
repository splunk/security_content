---
title: "Active Directory Lateral Movement"
last_modified_at: 2021-12-09
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Actions on Objectives
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate tactics, techniques, and procedures around how attackers move laterally within an Active Directory environment. Since lateral movement is often a necessary step in a breach, it is important for cyber defenders to deploy detection coverage.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-12-09
- **Author**: David Dorsey, Mauricio Velazco Splunk
- **ID**: 399d65dc-1f08-499b-a259-aad9051f38ad

#### Narrative

Once attackers gain a foothold within an enterprise, they will seek to expand their accesses and leverage techniques that facilitate lateral movement. Attackers will often spend quite a bit of time and effort moving laterally. Because lateral movement renders an attacker the most vulnerable to detection, it's an excellent focus for detection and investigation.\
Indications of lateral movement in an Active Directory network can include the abuse of system utilities (such as `psexec.exe`), unauthorized use of remote desktop services, `file/admin$` shares, WMI, PowerShell, Service Control Manager, the DCOM protocol, WinRM or the abuse of scheduled tasks. Organizations must be extra vigilant in detecting lateral movement techniques and look for suspicious activity in and around high-value strategic network assets, such as Active Directory, which are often considered the primary target or "crown jewels" to a persistent threat actor.\
An adversary can use lateral movement for multiple purposes, including remote execution of tools, pivoting to additional systems, obtaining access to specific information or files, access to additional credentials, exfiltrating data, or delivering a secondary effect. Adversaries may use legitimate credentials alongside inherent network and operating-system functionality to remotely connect to other systems and remain under the radar of network defenders.\
If there is evidence of lateral movement, it is imperative for analysts to collect evidence of the associated offending hosts. For example, an attacker might leverage host A to gain access to host B. From there, the attacker may try to move laterally to host C. In this example, the analyst should gather as much information as possible from all three hosts. \
 It is also important to collect authentication logs for each host, to ensure that the offending accounts are well-documented. Analysts should account for all processes to ensure that the attackers did not install unauthorized software.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Activity Related to Pass the Hash Attacks](/endpoint/detect_activity_related_to_pass_the_hash_attacks/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Hash](/tags/#pass-the-hash)| TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution)| Hunting |
| [Executable File Written in Administrative SMB Share](/endpoint/executable_file_written_in_administrative_smb_share/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/impacket_lateral_movement_commandline_parameters/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service)| TTP |
| [Interactive Session on Remote Endpoint with PowerShell](/endpoint/interactive_session_on_remote_endpoint_with_powershell/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management)| TTP |
| [Mmc LOLBAS Execution Process Spawn](/endpoint/mmc_lolbas_execution_process_spawn/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model)| TTP |
| [Possible Lateral Movement PowerShell Spawn](/endpoint/possible_lateral_movement_powershell_spawn/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Remote Management](/tags/#windows-remote-management), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Scheduled Task](/tags/#scheduled-task), [Windows Service](/tags/#windows-service), [PowerShell](/tags/#powershell)| TTP |
| [Remote Process Instantiation via DCOM and PowerShell](/endpoint/remote_process_instantiation_via_dcom_and_powershell/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model)| TTP |
| [Remote Process Instantiation via DCOM and PowerShell Script Block](/endpoint/remote_process_instantiation_via_dcom_and_powershell_script_block/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model)| TTP |
| [Remote Process Instantiation via WinRM and PowerShell](/endpoint/remote_process_instantiation_via_winrm_and_powershell/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management)| TTP |
| [Remote Process Instantiation via WinRM and PowerShell Script Block](/endpoint/remote_process_instantiation_via_winrm_and_powershell_script_block/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management)| TTP |
| [Remote Process Instantiation via WinRM and Winrs](/endpoint/remote_process_instantiation_via_winrm_and_winrs/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management)| TTP |
| [Remote Process Instantiation via WMI](/endpoint/remote_process_instantiation_via_wmi/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Remote Process Instantiation via WMI and PowerShell](/endpoint/remote_process_instantiation_via_wmi_and_powershell/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Remote Process Instantiation via WMI and PowerShell Script Block](/endpoint/remote_process_instantiation_via_wmi_and_powershell_script_block/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Scheduled Task Creation on Remote Endpoint using At](/endpoint/scheduled_task_creation_on_remote_endpoint_using_at/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [At (Windows)](/tags/#at-(windows))| TTP |
| [Scheduled Task Initiation on Remote Endpoint](/endpoint/scheduled_task_initiation_on_remote_endpoint/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task)| TTP |
| [Schtasks scheduling job on remote system](/endpoint/schtasks_scheduling_job_on_remote_system/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Services LOLBAS Execution Process Spawn](/endpoint/services_lolbas_execution_process_spawn/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service)| TTP |
| [Short Lived Scheduled Task](/endpoint/short_lived_scheduled_task/) | [Scheduled Task](/tags/#scheduled-task)| TTP |
| [Svchost LOLBAS Execution Process Spawn](/endpoint/svchost_lolbas_execution_process_spawn/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task)| TTP |
| [Windows Service Created With Suspicious Service Path](/endpoint/windows_service_created_with_suspicious_service_path/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution)| TTP |
| [Windows Service Created Within Public Path](/endpoint/windows_service_created_within_public_path/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service)| TTP |
| [Windows Service Creation on Remote Endpoint](/endpoint/windows_service_creation_on_remote_endpoint/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service)| TTP |
| [Windows Service Creation Using Registry Entry](/endpoint/windows_service_creation_using_registry_entry/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness)| TTP |
| [Windows Service Initiation on Remote Endpoint](/endpoint/windows_service_initiation_on_remote_endpoint/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service)| TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Wmiprsve LOLBAS Execution Process Spawn](/endpoint/wmiprsve_lolbas_execution_process_spawn/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Wsmprovhost LOLBAS Execution Process Spawn](/endpoint/wsmprovhost_lolbas_execution_process_spawn/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management)| TTP |
| [Randomly Generated Scheduled Task Name](/endpoint/randomly_generated_scheduled_task_name/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task)| Hunting |
| [Randomly Generated Windows Service Name](/endpoint/randomly_generated_windows_service_name/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service)| Hunting |
| [Remote Desktop Process Running On System](/endpoint/remote_desktop_process_running_on_system/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services)| Hunting |
| [Unusual Number of Computer Service Tickets Requested](/endpoint/unusual_number_of_computer_service_tickets_requested/) | [Valid Accounts](/tags/#valid-accounts)| Hunting |
| [Unusual Number of Remote Endpoint Authentication Events](/endpoint/unusual_number_of_remote_endpoint_authentication_events/) | [Valid Accounts](/tags/#valid-accounts)| Hunting |
| [Remote Desktop Network Traffic](/network/remote_desktop_network_traffic/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services)| Anomaly |

#### Reference

* [https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html](https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html)
* [http://www.irongeek.com/i.php?page=videos/derbycon7/t405-hunting-lateral-movement-for-fun-and-profit-mauricio-velazco](http://www.irongeek.com/i.php?page=videos/derbycon7/t405-hunting-lateral-movement-for-fun-and-profit-mauricio-velazco)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/active_directory_lateral_movement.yml) \| *version*: **3**