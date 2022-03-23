---
title: "Data Destruction"
last_modified_at: 2022-02-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the data destruction, including deleting files, overwriting files, wiping disk and encrypting files.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-02-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: 4ae5c0d1-cebd-47d1-bfce-71bf096e38aa

#### Narrative

Adversaries may use this technique to maximize the impact on the target organization in operations where network wide availability interruption is the goal.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux DD File Overwrite](/endpoint/linux_dd_file_overwrite/) | [Data Destruction](/tags/#data-destruction)| TTP |
| [Windows Disable Memory Crash Dump](/endpoint/windows_disable_memory_crash_dump/) | [Data Destruction](/tags/#data-destruction)| TTP |
| [Windows File Without Extension In Critical Folder](/endpoint/windows_file_without_extension_in_critical_folder/) | [Data Destruction](/tags/#data-destruction)| TTP |
| [Windows Raw Access To Disk Volume Partition](/endpoint/windows_raw_access_to_disk_volume_partition/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe)| Anomaly |

#### Reference

* [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)
* [https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/](https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/)
* [https://www.picussecurity.com/blog/a-brief-history-and-further-technical-analysis-of-sodinokibi-ransomware](https://www.picussecurity.com/blog/a-brief-history-and-further-technical-analysis-of-sodinokibi-ransomware)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/data_destruction.yml) \| *version*: **1**