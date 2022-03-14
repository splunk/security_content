---
title: "HAFNIUM Group"
last_modified_at: 2021-03-03
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Actions on Objectives
  - Command & Control
  - Exploitation
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

HAFNIUM group was identified by Microsoft as exploiting 4 Microsoft Exchange CVEs in the wild - CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 and CVE-2021-27065.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-03-03
- **Author**: Michael Haag, Splunk
- **ID**: beae2ab0-7c3f-11eb-8b63-acde48001122

#### Narrative

On Tuesday, March 2, 2021, Microsoft released a set of security patches for its mail server, Microsoft Exchange. These patches respond to a group of vulnerabilities known to impact Exchange 2013, 2016, and 2019. It is important to note that an Exchange 2010 security update has also been issued, though the CVEs do not reference that version as being vulnerable.\
While the CVEs do not shed much light on the specifics of the vulnerabilities or exploits, the first vulnerability (CVE-2021-26855) has a remote network attack vector that allows the attacker, a group Microsoft named HAFNIUM, to authenticate as the Exchange server. Three additional vulnerabilities (CVE-2021-26857, CVE-2021-26858, and CVE-2021-27065) were also identified as part of this activity. When chained together along with CVE-2021-26855 for initial access, the attacker would have complete control over the Exchange server. This includes the ability to run code as SYSTEM and write to any path on the server.\
The following Splunk detections assist with identifying the HAFNIUM groups tradecraft and methodology.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Dump LSASS via procdump Rename](/deprecated/dump_lsass_via_procdump_rename/) | [LSASS Memory](/tags/#lsass-memory)| Hunting |
| [Any Powershell DownloadString](/endpoint/any_powershell_downloadstring/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Detect Exchange Web Shell](/endpoint/detect_exchange_web_shell/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |
| [Detect New Local Admin account](/endpoint/detect_new_local_admin_account/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account)| TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares)| TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution)| Hunting |
| [Dump LSASS via comsvcs DLL](/endpoint/dump_lsass_via_comsvcs_dll/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Dump LSASS via procdump](/endpoint/dump_lsass_via_procdump/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/malicious_powershell_process_-_execution_policy_bypass/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Nishang PowershellTCPOneLine](/endpoint/nishang_powershelltcponeline/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Ntdsutil Export NTDS](/endpoint/ntdsutil_export_ntds/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [PowerShell - Connect To Internet With Hidden Window](/endpoint/powershell_-_connect_to_internet_with_hidden_window/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Set Default PowerShell Execution Policy To Unrestricted or Bypass](/endpoint/set_default_powershell_execution_policy_to_unrestricted_or_bypass/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Unified Messaging Service Spawning a Process](/endpoint/unified_messaging_service_spawning_a_process/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |
| [W3WP Spawning Shell](/endpoint/w3wp_spawning_shell/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell)| TTP |
| [Email servers sending high volume traffic to hosts](/application/email_servers_sending_high_volume_traffic_to_hosts/) | [Email Collection](/tags/#email-collection), [Remote Email Collection](/tags/#remote-email-collection)| Anomaly |

#### Reference

* [https://www.splunk.com/en_us/blog/security/detecting-hafnium-exchange-server-zero-day-activity-in-splunk.html](https://www.splunk.com/en_us/blog/security/detecting-hafnium-exchange-server-zero-day-activity-in-splunk.html)
* [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
* [https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)
* [https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/](https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/hafnium_group.yml) \| *version*: **1**