---
title: "Ryuk Ransomware"
last_modified_at: 2020-11-06
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Ryuk ransomware, including looking for file writes associated with Ryuk, Stopping Security Access Manager, DisableAntiSpyware registry key modification, suspicious psexec use, and more.

- **ID**: 507edc74-13d5-4339-878e-b9744ded1f35
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-11-06
- **Author**: Jose Hernandez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [BCDEdit Failure Recovery Modification](/endpoint/bcdedit_failure_recovery_modification/) | None | TTP |
| [Common Ransomware Extensions](/endpoint/common_ransomware_extensions/) | None | Hunting |
| [Common Ransomware Notes](/endpoint/common_ransomware_notes/) | None | Hunting |
| [NLTest Domain Trust Discovery](/endpoint/nltest_domain_trust_discovery/) | None | TTP |
| [Remote Desktop Network Bruteforce](/network/remote_desktop_network_bruteforce/) | None | TTP |
| [Remote Desktop Network Traffic](/network/remote_desktop_network_traffic/) | None | Anomaly |
| [Ryuk Test Files Detected](/endpoint/ryuk_test_files_detected/) | None | TTP |
| [Ryuk Wake on LAN Command](/endpoint/ryuk_wake_on_lan_command/) | None | TTP |
| [Spike in File Writes](/endpoint/spike_in_file_writes/) | None | Anomaly |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | None | Anomaly |
| [WBAdmin Delete System Backups](/endpoint/wbadmin_delete_system_backups/) | None | TTP |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/winevent_scheduled_task_created_within_public_path/) | None | TTP |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/winevent_scheduled_task_created_to_spawn_shell/) | None | TTP |
| [Windows DisableAntiSpyware Registry](/endpoint/windows_disableantispyware_registry/) | None | TTP |
| [Windows Security Account Manager Stopped](/endpoint/windows_security_account_manager_stopped/) | None | TTP |

#### Reference

* [https://www.splunk.com/en_us/blog/security/detecting-ryuk-using-splunk-attack-range.html](https://www.splunk.com/en_us/blog/security/detecting-ryuk-using-splunk-attack-range.html)
* [https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/](https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/)
* [https://us-cert.cisa.gov/ncas/alerts/aa20-302a](https://us-cert.cisa.gov/ncas/alerts/aa20-302a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ryuk_ransomware.yml) \| *version*: **1**