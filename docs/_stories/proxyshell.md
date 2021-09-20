---
title: "ProxyShell"
last_modified_at: 2021-08-24
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

ProxyShell is a chain of exploits targeting on-premise Microsoft Exchange Server - CVE-2021-34473, CVE-2021-34523, and CVE-2021-31207.

- **ID**: 413bb68e-04e2-11ec-a835-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-24
- **Author**: Michael Haag, Teoderick Contreras, Mauricio Velazco, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Exchange Web Shell](/endpoint/detect_exchange_web_shell/) | None | TTP |
| [Exchange PowerShell Abuse via SSRF](/endpoint/exchange_powershell_abuse_via_ssrf/) | None | TTP |
| [Exchange PowerShell Module Usage](/endpoint/exchange_powershell_module_usage/) | None | TTP |
| [W3WP Spawning Shell](/endpoint/w3wp_spawning_shell/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/](https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/)
* [https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
* [https://www.youtube.com/watch?v=FC6iHw258RI](https://www.youtube.com/watch?v=FC6iHw258RI)
* [https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do](https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do)
* [https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf)



_version_: 1