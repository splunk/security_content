---
title: "Spearphishing Attachments"
last_modified_at: 2019-04-29
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Detect signs of malicious payloads that may indicate that your environment has been breached via a phishing attack.

- **ID**: 57226b40-94f3-4ce5-b101-a75f67759c27
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2019-04-29
- **Author**: Splunk Research Team, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Outlook exe writing a zip file](/endpoint/detect_outlook_exe_writing_a_zip_file/) | None | TTP |
| [Excel Spawning PowerShell](/endpoint/excel_spawning_powershell/) | None | TTP |
| [Excel Spawning Windows Script Host](/endpoint/excel_spawning_windows_script_host/) | None | TTP |
| [Office Application Spawn rundll32 process](/endpoint/office_application_spawn_rundll32_process/) | None | TTP |
| [Office Document Creating Schedule Task](/endpoint/office_document_creating_schedule_task/) | None | TTP |
| [Office Document Executing Macro Code](/endpoint/office_document_executing_macro_code/) | None | TTP |
| [Office Document Spawned Child Process To Download](/endpoint/office_document_spawned_child_process_to_download/) | None | TTP |
| [Office Product Spawning BITSAdmin](/endpoint/office_product_spawning_bitsadmin/) | None | TTP |
| [Office Product Spawning CertUtil](/endpoint/office_product_spawning_certutil/) | None | TTP |
| [Office Product Spawning MSHTA](/endpoint/office_product_spawning_mshta/) | None | TTP |
| [Office Product Spawning Rundll32 with no DLL](/endpoint/office_product_spawning_rundll32_with_no_dll/) | None | TTP |
| [Office Product Spawning Wmic](/endpoint/office_product_spawning_wmic/) | None | TTP |
| [Process Creating LNK file in Suspicious Location](/endpoint/process_creating_lnk_file_in_suspicious_location/) | None | TTP |
| [Winword Spawning Cmd](/endpoint/winword_spawning_cmd/) | None | TTP |
| [Winword Spawning PowerShell](/endpoint/winword_spawning_powershell/) | None | TTP |

#### Reference

* [https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html](https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/spearphishing_attachments.yml) \| *version*: **1**