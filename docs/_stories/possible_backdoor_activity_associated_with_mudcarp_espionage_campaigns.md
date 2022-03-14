---
title: "Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns"
last_modified_at: 2020-01-22
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Command & Control
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your environment for suspicious behaviors that resemble the techniques employed by the MUDCARP threat group.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-01-22
- **Author**: iDefense Cyber Espionage Team, iDefense
- **ID**: 988C59C5-0A1C-45B6-A555-0C62276E327E

#### Narrative

This story was created as a joint effort between iDefense and Splunk.\
iDefense analysts have recently discovered a Windows executable file that, upon execution, spoofs a decryption tool and then drops a file that appears to be the custom-built javascript backdoor, "Orz," which is associated with the threat actors known as MUDCARP (as well as "temp.Periscope" and "Leviathan"). The file is executed using Wscript.\
The MUDCARP techniques include the use of the compressed-folders module from Microsoft, zipfldr.dll, with RouteTheCall export to run the malicious process or command. After a successful reboot, the malware is made persistent by a manipulating `[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]'help'='c:\\windows\\system32\\rundll32.exe c:\\windows\\system32\\zipfldr.dll,RouteTheCall c:\\programdata\\winapp.exe'`. Though this technique is not exclusive to MUDCARP, it has been spotted in the group's arsenal of advanced techniques seen in the wild.\
This Analytic Story searches for evidence of tactics, techniques, and procedures (TTPs) that allow for the use of a endpoint detection-and-response (EDR) bypass technique to mask the true parent of a malicious process. It can also be set as a registry key for further sandbox evasion and to allow the malware to launch only after reboot.\
If behavioral searches included in this story yield positive hits, iDefense recommends conducting IOC searches for the following:\
\
1. www.chemscalere[.]com\
1. chemscalere[.]com\
1. about.chemscalere[.]com\
1. autoconfig.chemscalere[.]com\
1. autodiscover.chemscalere[.]com\
1. catalog.chemscalere[.]com\
1. cpanel.chemscalere[.]com\
1. db.chemscalere[.]com\
1. ftp.chemscalere[.]com\
1. mail.chemscalere[.]com\
1. news.chemscalere[.]com\
1. update.chemscalere[.]com\
1. webmail.chemscalere[.]com\
1. www.candlelightparty[.]org\
1. candlelightparty[.]org\
1. newapp.freshasianews[.]comIn addition, iDefense also recommends that organizations review their environments for activity related to the following hashes:\
\
1. cd195ee448a3657b5c2c2d13e9c7a2e2\
1. b43ad826fe6928245d3c02b648296b43\
1. 889a9b52566448231f112a5ce9b5dfaf\
1. b8ec65dab97cdef3cd256cc4753f0c54\
1. 04d83cd3813698de28cfbba326d7647c

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [First time seen command line argument](/deprecated/first_time_seen_command_line_argument/) | [PowerShell](/tags/#powershell), [Windows Command Shell](/tags/#windows-command-shell)| Hunting |
| [PowerShell - Connect To Internet With Hidden Window](/endpoint/powershell_-_connect_to_internet_with_hidden_window/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) | None| Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) | None| Anomaly |

#### Reference

* [https://www.infosecurity-magazine.com/news/scope-of-mudcarp-attacks-highlight-1/](https://www.infosecurity-magazine.com/news/scope-of-mudcarp-attacks-highlight-1/)
* [http://blog.amossys.fr/badflick-is-not-so-bad.html](http://blog.amossys.fr/badflick-is-not-so-bad.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/possible_backdoor_activity_associated_with_mudcarp_espionage_campaigns.yml) \| *version*: **1**