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

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Clop ransomware, including looking for file writes associated with Clope, encrypting network shares, deleting and resizing shadow volume storage, registry key modification, deleting of security logs, and more.

- **ID**: 5a6f6849-1a26-4fae-aa05-fa730556eeb6
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-17
- **Author**: Rod Soto, Teoderick Contreras, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clop Common Exec Parameter](/endpoint/clop_common_exec_parameter/) | None | TTP |
| [Clop Ransomware Known Service Name](/endpoint/clop_ransomware_known_service_name/) | None | TTP |
| [Common Ransomware Extensions](/endpoint/common_ransomware_extensions/) | None | Hunting |
| [Common Ransomware Notes](/endpoint/common_ransomware_notes/) | None | Hunting |
| [Create Service In Suspicious File Path](/endpoint/create_service_in_suspicious_file_path/) | None | TTP |
| [Deleting Shadow Copies](/endpoint/deleting_shadow_copies/) | None | TTP |
| [High File Deletion Frequency](/endpoint/high_file_deletion_frequency/) | None | Anomaly |
| [High Process Termination Frequency](/endpoint/high_process_termination_frequency/) | None | Anomaly |
| [Process Deleting Its Process File Path](/endpoint/process_deleting_its_process_file_path/) | None | TTP |
| [Ransomware Notes bulk creation](/endpoint/ransomware_notes_bulk_creation/) | None | Anomaly |
| [Resize ShadowStorage volume](/endpoint/resize_shadowstorage_volume/) | None | TTP |
| [Resize Shadowstorage Volume](/endpoint/resize_shadowstorage_volume/) | None | TTP |
| [Suspicious Event Log Service Behavior](/endpoint/suspicious_event_log_service_behavior/) | None | TTP |
| [Suspicious wevtutil Usage](/endpoint/suspicious_wevtutil_usage/) | None | TTP |
| [WevtUtil Usage To Clear Logs](/endpoint/wevtutil_usage_to_clear_logs/) | None | TTP |
| [Windows Event Log Cleared](/endpoint/windows_event_log_cleared/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://www.hhs.gov/sites/default/files/analyst-note-cl0p-tlp-white.pdf](https://www.hhs.gov/sites/default/files/analyst-note-cl0p-tlp-white.pdf)
* [https://securityaffairs.co/wordpress/115250/data-breach/qualys-clop-ransomware.html](https://securityaffairs.co/wordpress/115250/data-breach/qualys-clop-ransomware.html)
* [https://www.darkreading.com/attacks-breaches/qualys-is-the-latest-victim-of-accellion-data-breach/d/d-id/1340323](https://www.darkreading.com/attacks-breaches/qualys-is-the-latest-victim-of-accellion-data-breach/d/d-id/1340323)



_version_: 1