---
title: "W3WP Spawning Shell"
excerpt: "Server Software Component
, Web Shell
"
categories:
  - Endpoint
last_modified_at: 2021-03-03
toc: true
toc_label: ""
tags:
  - Server Software Component
  - Web Shell
  - Persistence
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-34473
  - CVE-2021-34523
  - CVE-2021-31207
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This query identifies a shell, PowerShell.exe or Cmd.exe, spawning from W3WP.exe, or IIS. In addition to IIS logs, this behavior with an EDR product will capture potential webshell activity, similar to the HAFNIUM Group abusing CVEs, on publicly available Exchange mail servers. During triage, review the parent process and child process of the shell being spawned. Review the command-line arguments and any file modifications that may occur. Identify additional parallel process, child processes, that may highlight further commands executed. After triaging, work to contain the threat and patch the system that is vulnerable.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-03-03
- **Author**: Michael Haag, Splunk
- **ID**: 0f03423c-7c6a-11eb-bc47-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1505](https://attack.mitre.org/techniques/T1505/) | Server Software Component | Persistence |

| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | Persistence |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process_name) as process_name values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=w3wp.exe AND `process_cmd` OR `process_powershell` by Processes.dest Processes.parent_process Processes.original_file_name Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `w3wp_spawning_shell_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_cmd](https://github.com/splunk/security_content/blob/develop/macros/process_cmd.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_powershell](https://github.com/splunk/security_content/blob/develop/macros/process_powershell.yml)

Note that `w3wp_spawning_shell_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Baseline your environment before production. It is possible build systems using IIS will spawn cmd.exe to perform a software build. Filter as needed.

#### Associated Analytic story
* [HAFNIUM Group](/stories/hafnium_group)
* [ProxyShell](/stories/proxyshell)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | Possible Web Shell execution on $dest$ |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-34473](https://nvd.nist.gov/vuln/detail/CVE-2021-34473) | Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206. | 10.0 |
| [CVE-2021-34523](https://nvd.nist.gov/vuln/detail/CVE-2021-34523) | Microsoft Exchange Server Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-33768, CVE-2021-34470. | 7.5 |
| [CVE-2021-31207](https://nvd.nist.gov/vuln/detail/CVE-2021-31207) | Microsoft Exchange Server Security Feature Bypass Vulnerability | 6.5 |



#### Reference

* [https://www.microsoft.com/security/blog/2020/02/04/ghost-in-the-shell-investigating-web-shell-attacks/](https://www.microsoft.com/security/blog/2020/02/04/ghost-in-the-shell-investigating-web-shell-attacks/)
* [https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
* [https://www.youtube.com/watch?v=FC6iHw258RI](https://www.youtube.com/watch?v=FC6iHw258RI)
* [https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do](https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/w3wp_spawning_shell.yml) \| *version*: **2**