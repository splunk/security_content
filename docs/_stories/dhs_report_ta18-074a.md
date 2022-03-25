---
title: "DHS Report TA18-074A"
last_modified_at: 2020-01-22
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Actions on Objectives
  - Command & Control
  - Exploitation
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for suspicious activities associated with DHS Technical Alert US-CERT TA18-074A. Some of the activities that adversaries used in these compromises included spearfishing attacks, malware, watering-hole domains, many and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-01-22
- **Author**: Rico Valdez, Splunk
- **ID**: 0c016e5c-88be-4e2c-8c6c-c2b55b4fb4ef

#### Narrative

The frequency of nation-state cyber attacks has increased significantly over the last decade. Employing numerous tactics and techniques, these attacks continue to escalate in complexity. \
There is a wide range of motivations for these state-sponsored hacks, including stealing valuable corporate, military, or diplomatic data&#1151;all of which could confer advantages in various arenas. They may also target critical infrastructure. \
One joint Technical Alert (TA) issued by the Department of Homeland and the FBI in mid-March of 2018 attributed some cyber activity targeting utility infrastructure to operatives sponsored by the Russian government. The hackers executed spearfishing attacks, installed malware, employed watering-hole domains, and more. While they caused no physical damage, the attacks provoked fears that a nation-state could turn off water, redirect power, or compromise a nuclear power plant.\
Suspicious activities--spikes in SMB traffic, processes that launch netsh (to modify the network configuration), suspicious registry modifications, and many more--may all be events you may wish to investigate further. While the use of these technique may be an indication that a nation-state actor is attempting to compromise your environment, it is important to note that these techniques are often employed by other groups, as well.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [First time seen command line argument](/deprecated/first_time_seen_command_line_argument/) | [PowerShell](/tags/#powershell), [Windows Command Shell](/tags/#windows-command-shell)| Hunting |
| [Create local admin accounts using net exe](/endpoint/create_local_admin_accounts_using_net_exe/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account)| TTP |
| [Detect New Local Admin account](/endpoint/detect_new_local_admin_account/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account)| TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution)| Hunting |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/malicious_powershell_process_-_execution_policy_bypass/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Processes launching netsh](/endpoint/processes_launching_netsh/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/scheduled_task_deleted_or_created_via_cmd/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Single Letter Process On Endpoint](/endpoint/single_letter_process_on_endpoint/) | [User Execution](/tags/#user-execution), [Malicious File](/tags/#malicious-file)| TTP |
| [Suspicious Reg exe Process](/endpoint/suspicious_reg_exe_process/) | [Modify Registry](/tags/#modify-registry)| TTP |
| [Detect Outbound SMB Traffic](/network/detect_outbound_smb_traffic/) | [File Transfer Protocols](/tags/#file-transfer-protocols), [Application Layer Protocol](/tags/#application-layer-protocol)| TTP |
| [SMB Traffic Spike](/network/smb_traffic_spike/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Remote Services](/tags/#remote-services)| Anomaly |
| [SMB Traffic Spike - MLTK](/network/smb_traffic_spike_-_mltk/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Remote Services](/tags/#remote-services)| Anomaly |

#### Reference

* [https://www.us-cert.gov/ncas/alerts/TA18-074A](https://www.us-cert.gov/ncas/alerts/TA18-074A)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dhs_report_ta18-074a.yml) \| *version*: **2**