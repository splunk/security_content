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

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect signs of malicious payloads that may indicate that your environment has been breached via a phishing attack.

- **ID**: 57226b40-94f3-4ce5-b101-a75f67759c27
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2019-04-29
- **Author**: Splunk Research Team, Splunk

#### Narrative

Despite its simplicity, phishing remains the most pervasive and dangerous cyberthreat. In fact, research shows that as many as [91% of all successful attacks](https://digitalguardian.com/blog/91-percent-cyber-attacks-start-phishing-email-heres-how-protect-against-phishing) are initiated via a phishing email. \
As most people know, these emails use fraudulent domains, [email scraping](https://www.cyberscoop.com/emotet-trojan-phishing-scraping-templates-cofense-geodo/), familiar contact names inserted as senders, and other tactics to lure targets into clicking a malicious link, opening an attachment with a [nefarious payload](https://www.cyberscoop.com/emotet-trojan-phishing-scraping-templates-cofense-geodo/), or entering sensitive personal information that perpetrators may intercept. This attack technique requires a relatively low level of skill and allows adversaries to easily cast a wide net. Worse, because its success relies on the gullibility of humans, it's impossible to completely "automate" it out of your environment. However, you can use ES and ESCU to detect and investigate potentially malicious payloads injected into your environment subsequent to a phishing attack. \
While any kind of file may contain a malicious payload, some are more likely to be perceived as benign (and thus more often escape notice) by the average victim&#151;especially when the attacker sends an email that seems to be from one of their contacts. An example is Microsoft Office files. Most corporate users are familiar with documents with the following suffixes: .doc/.docx (MS Word), .xls/.xlsx (MS Excel), and .ppt/.pptx (MS PowerPoint), so they may click without a second thought, slashing a hole in their organizations' security. \
Following is a typical series of events, according to an [article by Trend Micro](https://blog.trendmicro.com/trendlabs-security-intelligence/rising-trend-attackers-using-lnk-files-download-malware/):\
1. Attacker sends a phishing email. Recipient downloads the attached file, which is typically a .docx or .zip file with an embedded .lnk file\
1. The .lnk file executes a PowerShell script\
1. Powershell executes a reverse shell, rendering the exploit successful </ol>As a side note, adversaries are likely to use a tool like Empire to craft and obfuscate payloads and their post-injection activities, such as [exfiltration, lateral movement, and persistence](https://github.com/EmpireProject/Empire).\
This Analytic Story focuses on detecting signs that a malicious payload has been injected into your environment. For example, one search detects outlook.exe writing a .zip file. Another looks for suspicious .lnk files launching processes.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Outlook exe writing a zip file](/endpoint/detect_outlook_exe_writing_a_zip_file/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Security Account Manager](/tags/#security-account-manager), [Spearphishing Link](/tags/#spearphishing-link) | TTP |
| [Excel Spawning PowerShell](/endpoint/excel_spawning_powershell/) | [Security Account Manager](/tags/#security-account-manager) | TTP |
| [Excel Spawning Windows Script Host](/endpoint/excel_spawning_windows_script_host/) | [Security Account Manager](/tags/#security-account-manager) | TTP |
| [Office Application Spawn rundll32 process](/endpoint/office_application_spawn_rundll32_process/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Document Creating Schedule Task](/endpoint/office_document_creating_schedule_task/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Document Executing Macro Code](/endpoint/office_document_executing_macro_code/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Document Spawned Child Process To Download](/endpoint/office_document_spawned_child_process_to_download/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawning BITSAdmin](/endpoint/office_product_spawning_bitsadmin/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawning CertUtil](/endpoint/office_product_spawning_certutil/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawning MSHTA](/endpoint/office_product_spawning_mshta/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawning Rundll32 with no DLL](/endpoint/office_product_spawning_rundll32_with_no_dll/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Office Product Spawning Wmic](/endpoint/office_product_spawning_wmic/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Process Creating LNK file in Suspicious Location](/endpoint/process_creating_lnk_file_in_suspicious_location/) | [Spearphishing Link](/tags/#spearphishing-link) | TTP |
| [Winword Spawning Cmd](/endpoint/winword_spawning_cmd/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |
| [Winword Spawning PowerShell](/endpoint/winword_spawning_powershell/) | [Spearphishing Attachment](/tags/#spearphishing-attachment) | TTP |

#### Reference

* [https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html](https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/spearphishing_attachments.yml) \| *version*: **1**