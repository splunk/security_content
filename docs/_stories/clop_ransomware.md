---
title: "Clop Ransomware"
last_modified_at: 2021-03-17
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Clop ransomware, including looking for file writes associated with Clope, encrypting network shares, deleting and resizing shadow volume storage, registry key modification, deleting of security logs, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-17
- **Author**: Rod Soto, Teoderick Contreras, Splunk
- **ID**: 5a6f6849-1a26-4fae-aa05-fa730556eeb6

#### Narrative

Clop ransomware campaigns targeting healthcare and other vertical sectors, involve the use of ransomware payloads along with exfiltration of data per HHS bulletin. Malicious actors demand payment for ransome of data and threaten deletion and exposure of exfiltrated data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clop Common Exec Parameter](/endpoint/clop_common_exec_parameter/) | [User Execution](/tags/#user-execution), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Data Destruction](/tags/#data-destruction), [Service Execution](/tags/#service-execution), [Inhibit System Recovery](/tags/#inhibit-system-recovery), [Data Encrypted for Impact](/tags/#data-encrypted-for-impact), [Security Account Manager](/tags/#security-account-manager), [Service Stop](/tags/#service-stop), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Clop Ransomware Known Service Name](/endpoint/clop_ransomware_known_service_name/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [Common Ransomware Extensions](/endpoint/common_ransomware_extensions/) | [Data Destruction](/tags/#data-destruction) | Hunting |
| [Common Ransomware Notes](/endpoint/common_ransomware_notes/) | [Data Destruction](/tags/#data-destruction) | Hunting |
| [Create Service In Suspicious File Path](/endpoint/create_service_in_suspicious_file_path/) | [Service Execution](/tags/#service-execution) | TTP |
| [Deleting Shadow Copies](/endpoint/deleting_shadow_copies/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery), [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [High File Deletion Frequency](/endpoint/high_file_deletion_frequency/) | [Data Destruction](/tags/#data-destruction) | Anomaly |
| [High Process Termination Frequency](/endpoint/high_process_termination_frequency/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | Anomaly |
| [Process Deleting Its Process File Path](/endpoint/process_deleting_its_process_file_path/) | [Security Account Manager](/tags/#security-account-manager) | TTP |
| [Ransomware Notes bulk creation](/endpoint/ransomware_notes_bulk_creation/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | Anomaly |
| [Resize ShadowStorage volume](/endpoint/resize_shadowstorage_volume/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | TTP |
| [Resize Shadowstorage Volume](/endpoint/resize_shadowstorage_volume/) | [Service Stop](/tags/#service-stop) | TTP |
| [Suspicious Event Log Service Behavior](/endpoint/suspicious_event_log_service_behavior/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Suspicious wevtutil Usage](/endpoint/suspicious_wevtutil_usage/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [WevtUtil Usage To Clear Logs](/endpoint/wevtutil_usage_to_clear_logs/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |
| [Windows Event Log Cleared](/endpoint/windows_event_log_cleared/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | TTP |

#### Reference

* [https://www.hhs.gov/sites/default/files/analyst-note-cl0p-tlp-white.pdf](https://www.hhs.gov/sites/default/files/analyst-note-cl0p-tlp-white.pdf)
* [https://securityaffairs.co/wordpress/115250/data-breach/qualys-clop-ransomware.html](https://securityaffairs.co/wordpress/115250/data-breach/qualys-clop-ransomware.html)
* [https://www.darkreading.com/attacks-breaches/qualys-is-the-latest-victim-of-accellion-data-breach/d/d-id/1340323](https://www.darkreading.com/attacks-breaches/qualys-is-the-latest-victim-of-accellion-data-breach/d/d-id/1340323)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/clop_ransomware.yml) \| *version*: **1**