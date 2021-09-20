---
title: "XMRig"
last_modified_at: 2021-05-07
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the xmrig monero, including looking for file writes associated with its payload, process command-line, defense evasion (killing services, deleting users, modifying files or folder permission, killing other malware or other coin miner) and hacking tools including Telegram as mean of command and control (C2) to download other files. Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability. One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive. (1) Servers and cloud-based (2) systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining.

- **ID**: 06723e6a-6bd8-4817-ace2-5fb8a7b06628
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-07
- **Author**: Teoderick Contreras, Rod Soto Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attacker Tools On Endpoint](/endpoint/attacker_tools_on_endpoint/) | None | TTP |
| [Attempt To Disable Services](/endpoint/attempt_to_disable_services/) | None | TTP |
| [Attempt To delete Services](/endpoint/attempt_to_delete_services/) | None | TTP |
| [Delete A Net User](/endpoint/delete_a_net_user/) | None | Anomaly |
| [Deleting Of Net Users](/endpoint/deleting_of_net_users/) | None | TTP |
| [Deny Permission using Cacls Utility](/endpoint/deny_permission_using_cacls_utility/) | None | TTP |
| [Disable Net User Account](/endpoint/disable_net_user_account/) | None | TTP |
| [Disable Windows App Hotkeys](/endpoint/disable_windows_app_hotkeys/) | None | TTP |
| [Disabling Net User Account](/endpoint/disabling_net_user_account/) | None | TTP |
| [Download Files Using Telegram](/endpoint/download_files_using_telegram/) | None | TTP |
| [Enumerate Users Local Group Using Telegram](/endpoint/enumerate_users_local_group_using_telegram/) | None | TTP |
| [Excessive Attempt To Disable Services](/endpoint/excessive_attempt_to_disable_services/) | None | Anomaly |
| [Excessive Service Stop Attempt](/endpoint/excessive_service_stop_attempt/) | None | Anomaly |
| [Excessive Usage Of Cacls App](/endpoint/excessive_usage_of_cacls_app/) | None | Anomaly |
| [Excessive Usage Of Net App](/endpoint/excessive_usage_of_net_app/) | None | Anomaly |
| [Excessive Usage Of Taskkill](/endpoint/excessive_usage_of_taskkill/) | None | Anomaly |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | None | TTP |
| [Grant Permission Using Cacls Utility](/endpoint/grant_permission_using_cacls_utility/) | None | TTP |
| [Hide User Account From Sign-In Screen](/endpoint/hide_user_account_from_sign-in_screen/) | None | TTP |
| [ICACLS Grant Command](/endpoint/icacls_grant_command/) | None | TTP |
| [Icacls Deny Command](/endpoint/icacls_deny_command/) | None | TTP |
| [Modify ACL permission To Files Or Folder](/endpoint/modify_acl_permission_to_files_or_folder/) | None | TTP |
| [Modify ACLs Permission Of Files Or Folders](/endpoint/modify_acls_permission_of_files_or_folders/) | None | Anomaly |
| [Process Kill Base On File Path](/endpoint/process_kill_base_on_file_path/) | None | TTP |
| [Schtasks Run Task On Demand](/endpoint/schtasks_run_task_on_demand/) | None | TTP |
| [Suspicious Driver Loaded Path](/endpoint/suspicious_driver_loaded_path/) | None | TTP |
| [Suspicious Process File Path](/endpoint/suspicious_process_file_path/) | None | TTP |
| [XMRIG Driver Loaded](/endpoint/xmrig_driver_loaded/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://github.com/xmrig/xmrig](https://github.com/xmrig/xmrig)
* [https://www.getmonero.org/resources/user-guides/mine-to-pool.html](https://www.getmonero.org/resources/user-guides/mine-to-pool.html)
* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)
* [https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/](https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/)



_version_: 1