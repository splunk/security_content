---
title: "BlackMatter Ransomware"
last_modified_at: 2021-09-06
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the BlackMatter ransomware, including looking for file writes associated with BlackMatter, force safe mode boot, autadminlogon account registry modification and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0da348a3-78a0-412e-ab27-2de9dd7f9fee

#### Narrative

BlackMatter ransomware campaigns targeting healthcare and other vertical sectors, involve the use of ransomware payloads along with exfiltration of data per HHS bulletin. Malicious actors demand payment for ransome of data and threaten deletion and exposure of exfiltrated data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Add DefaultUser And Password In Registry](/endpoint/add_defaultuser_and_password_in_registry/) | [Credentials in Registry](/tags/#credentials-in-registry), [Unsecured Credentials](/tags/#unsecured-credentials)| Anomaly |
| [Auto Admin Logon Registry Entry](/endpoint/auto_admin_logon_registry_entry/) | [Credentials in Registry](/tags/#credentials-in-registry), [Unsecured Credentials](/tags/#unsecured-credentials)| TTP |
| [Bcdedit Command Back To Normal Mode Boot](/endpoint/bcdedit_command_back_to_normal_mode_boot/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Change To Safe Mode With Network Config](/endpoint/change_to_safe_mode_with_network_config/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Known Services Killed by Ransomware](/endpoint/known_services_killed_by_ransomware/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery)| TTP |
| [Modification Of Wallpaper](/endpoint/modification_of_wallpaper/) | [Defacement](/tags/#defacement)| TTP |
| [Ransomware Notes bulk creation](/endpoint/ransomware_notes_bulk_creation/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact)| Anomaly |

#### Reference

* [https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/](https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/)
* [https://www.bleepingcomputer.com/news/security/blackmatter-ransomware-gang-rises-from-the-ashes-of-darkside-revil/](https://www.bleepingcomputer.com/news/security/blackmatter-ransomware-gang-rises-from-the-ashes-of-darkside-revil/)
* [https://blog.malwarebytes.com/ransomware/2021/07/blackmatter-a-new-ransomware-group-claims-link-to-darkside-revil/](https://blog.malwarebytes.com/ransomware/2021/07/blackmatter-a-new-ransomware-group-claims-link-to-darkside-revil/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/blackmatter_ransomware.yml) \| *version*: **1**