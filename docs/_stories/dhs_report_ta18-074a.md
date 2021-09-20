---
title: "DHS Report TA18-074A"
last_modified_at: 2020-01-22
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

#### Description

Monitor for suspicious activities associated with DHS Technical Alert US-CERT TA18-074A. Some of the activities that adversaries used in these compromises included spearfishing attacks, malware, watering-hole domains, many and more.

- **ID**: 0c016e5c-88be-4e2c-8c6c-c2b55b4fb4ef
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-01-22
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Create local admin accounts using net exe](/endpoint/create_local_admin_accounts_using_net_exe/) | None | TTP |
| [Detect New Local Admin account](/endpoint/detect_new_local_admin_account/) | None | TTP |
| [Detect Outbound SMB Traffic](/network/detect_outbound_smb_traffic/) | None | TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | None | TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | None | TTP |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/malicious_powershell_process_-_execution_policy_bypass/) | None | TTP |
| [Processes launching netsh](/endpoint/processes_launching_netsh/) | None | TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | None | TTP |
| [SMB Traffic Spike](/network/smb_traffic_spike/) | None | Anomaly |
| [SMB Traffic Spike - MLTK](/network/smb_traffic_spike_-_mltk/) | None | Anomaly |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | None | TTP |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/scheduled_task_deleted_or_created_via_cmd/) | None | TTP |
| [Single Letter Process On Endpoint](/endpoint/single_letter_process_on_endpoint/) | None | TTP |
| [Suspicious Reg exe Process](/endpoint/suspicious_reg_exe_process/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://www.us-cert.gov/ncas/alerts/TA18-074A](https://www.us-cert.gov/ncas/alerts/TA18-074A)



_version_: 2