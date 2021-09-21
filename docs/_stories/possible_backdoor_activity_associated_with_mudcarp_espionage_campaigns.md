---
title: "Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns"
last_modified_at: 2020-01-22
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Monitor your environment for suspicious behaviors that resemble the techniques employed by the MUDCARP threat group.

- **ID**: 988C59C5-0A1C-45B6-A555-0C62276E327E
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-01-22
- **Author**: iDefense Cyber Espionage Team, iDefense

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Malicious PowerShell Process - Connect To Internet With Hidden Window](/endpoint/malicious_powershell_process_-_connect_to_internet_with_hidden_window/) | None | TTP |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | None | TTP |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) | None | Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) | None | Anomaly |

#### Reference

* [https://www.infosecurity-magazine.com/news/scope-of-mudcarp-attacks-highlight-1/](https://www.infosecurity-magazine.com/news/scope-of-mudcarp-attacks-highlight-1/)
* [http://blog.amossys.fr/badflick-is-not-so-bad.html](http://blog.amossys.fr/badflick-is-not-so-bad.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/possible_backdoor_activity_associated_with_mudcarp_espionage_campaigns.yml) \| *version*: **1**