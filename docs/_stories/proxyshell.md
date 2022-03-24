---
title: "ProxyShell"
last_modified_at: 2021-08-24
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

ProxyShell is a chain of exploits targeting on-premise Microsoft Exchange Server - CVE-2021-34473, CVE-2021-34523, and CVE-2021-31207.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-24
- **Author**: Michael Haag, Teoderick Contreras, Mauricio Velazco, Splunk
- **ID**: 413bb68e-04e2-11ec-a835-acde48001122

#### Narrative

During Pwn2Own April 2021, a security researcher demonstrated an attack  chain targeting on-premise Microsoft Exchange Server. August 5th, the same researcher  publicly released further details and demonstrated the attack chain. CVE-2021-34473  Pre-auth path confusion leads to ACL Bypass (Patched in April by KB5001779)  CVE-2021-34523 - Elevation of privilege on Exchange PowerShell backend (Patched in April by KB5001779) . CVE-2021-31207 - Post-auth Arbitrary-File-Write  leads to RCE (Patched in May by KB5003435) Upon successful exploitation,  the remote attacker will have SYSTEM privileges on the Exchange Server. In addition    to remote access/execution, the adversary may be able to run Exchange PowerShell  Cmdlets to perform further actions.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Exchange Web Shell](/endpoint/detect_exchange_web_shell/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |
| [W3WP Spawning Shell](/endpoint/w3wp_spawning_shell/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell)| TTP |
| [Exchange PowerShell Abuse via SSRF](/endpoint/exchange_powershell_abuse_via_ssrf/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |
| [Exchange PowerShell Module Usage](/endpoint/exchange_powershell_module_usage/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [MS Exchange Mailbox Replication service writing Active Server Pages](/endpoint/ms_exchange_mailbox_replication_service_writing_active_server_pages/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |

#### Reference

* [https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/](https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/)
* [https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
* [https://www.youtube.com/watch?v=FC6iHw258RI](https://www.youtube.com/watch?v=FC6iHw258RI)
* [https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do](https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do)
* [https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/proxyshell.yml) \| *version*: **1**