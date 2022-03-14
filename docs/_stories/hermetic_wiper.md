---
title: "Hermetic Wiper"
last_modified_at: 2022-03-02
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

This analytic story contains detections that allow security analysts to detect and investigate unusual activities that might relate to the destructive malware targeting Ukrainian organizations also known as "Hermetic Wiper". This analytic story looks for abuse of Regsvr32, executables written in administrative SMB Share, suspicious processes, disabling of memory crash dump and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-02
- **Author**: Teoderick Contreras, Rod Soto, Michael Haag, Splunk
- **ID**: b7511c2e-9a10-11ec-99e3-acde48001122

#### Narrative

Hermetic Wiper is destructive malware operation found by Sentinel One targeting multiple organizations in Ukraine. This malicious payload corrupts Master Boot Records, uses signed drivers and manipulates NTFS attributes for file destruction.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CMD Carry Out String Command Parameter](/endpoint/cmd_carry_out_string_command_parameter/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Executable File Written in Administrative SMB Share](/endpoint/executable_file_written_in_administrative_smb_share/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | [Masquerading](/tags/#masquerading)| TTP |
| [Regsvr32 Silent and Install Param Dll Loading](/endpoint/regsvr32_silent_and_install_param_dll_loading/) | [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| Anomaly |
| [Suspicious Process File Path](/endpoint/suspicious_process_file_path/) | [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [Windows Disable Memory Crash Dump](/endpoint/windows_disable_memory_crash_dump/) | [Data Destruction](/tags/#data-destruction)| TTP |
| [Windows File Without Extension In Critical Folder](/endpoint/windows_file_without_extension_in_critical_folder/) | [Data Destruction](/tags/#data-destruction)| TTP |
| [Windows Modify Show Compress Color And Info Tip Registry](/endpoint/windows_modify_show_compress_color_and_info_tip_registry/) | [Modify Registry](/tags/#modify-registry)| TTP |
| [Windows Raw Access To Disk Volume Partition](/endpoint/windows_raw_access_to_disk_volume_partition/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe)| Anomaly |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/windows_raw_access_to_master_boot_record_drive/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe)| TTP |

#### Reference

* [https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/](https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/)
* [https://www.cisa.gov/uscert/ncas/alerts/aa22-057a](https://www.cisa.gov/uscert/ncas/alerts/aa22-057a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/hermetic_wiper.yml) \| *version*: **1**