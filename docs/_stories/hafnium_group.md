---
title: "HAFNIUM Group"
last_modified_at: 2021-03-03
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

#### Description

HAFNIUM group was identified by Microsoft as exploiting 4 Microsoft Exchange CVEs in the wild - CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 and CVE-2021-27065.

- **ID**: beae2ab0-7c3f-11eb-8b63-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-03-03
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadString](/endpoint/any_powershell_downloadstring/) | None | TTP |
| [Detect Exchange Web Shell](/endpoint/detect_exchange_web_shell/) | None | TTP |
| [Detect New Local Admin account](/endpoint/detect_new_local_admin_account/) | None | TTP |
| [Detect PsExec With accepteula Flag](/endpoint/detect_psexec_with_accepteula_flag/) | None | TTP |
| [Detect Renamed PSExec](/endpoint/detect_renamed_psexec/) | None | TTP |
| [Dump LSASS via comsvcs DLL](/endpoint/dump_lsass_via_comsvcs_dll/) | None | TTP |
| [Dump LSASS via procdump](/endpoint/dump_lsass_via_procdump/) | None | TTP |
| [Dump LSASS via procdump Rename](/endpoint/dump_lsass_via_procdump_rename/) | None | TTP |
| [Email servers sending high volume traffic to hosts](/application/email_servers_sending_high_volume_traffic_to_hosts/) | None | Anomaly |
| [Malicious PowerShell Process - Connect To Internet With Hidden Window](/endpoint/malicious_powershell_process_-_connect_to_internet_with_hidden_window/) | None | TTP |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/malicious_powershell_process_-_execution_policy_bypass/) | None | TTP |
| [Nishang PowershellTCPOneLine](/endpoint/nishang_powershelltcponeline/) | None | TTP |
| [Ntdsutil Export NTDS](/endpoint/ntdsutil_export_ntds/) | None | TTP |
| [Set Default PowerShell Execution Policy To Unrestricted or Bypass](/endpoint/set_default_powershell_execution_policy_to_unrestricted_or_bypass/) | None | TTP |
| [Unified Messaging Service Spawning a Process](/endpoint/unified_messaging_service_spawning_a_process/) | None | TTP |
| [W3WP Spawning Shell](/endpoint/w3wp_spawning_shell/) | None | TTP |

#### Reference

* [https://www.splunk.com/en_us/blog/security/detecting-hafnium-exchange-server-zero-day-activity-in-splunk.html](https://www.splunk.com/en_us/blog/security/detecting-hafnium-exchange-server-zero-day-activity-in-splunk.html)
* [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
* [https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)
* [https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/](https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/hafnium_group.yml) | _version_: **1**