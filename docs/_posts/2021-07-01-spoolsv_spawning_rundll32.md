---
title: "Spoolsv Spawning Rundll32"
excerpt: "Print Processors
, Boot or Logon Autostart Execution
"
categories:
  - Endpoint
last_modified_at: 2021-07-01
toc: true
toc_label: ""
tags:
  - Print Processors
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-34527
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a suspicious child process, `rundll32.exe`, with no command-line arguments being spawned from `spoolsv.exe`. This was identified during our testing of CVE-2021-34527 previously (CVE-2021-1675) or PrintNightmare. Typically, this is not normal behavior for `spoolsv.exe` to spawn a process. During triage, isolate the endpoint and review for source of exploitation. Capture any additional file modification events.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-07-01
- **Author**: Mauricio Velazco, Michael Haag, Splunk
- **ID**: 15d905f6-da6b-11eb-ab82-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1547.012](https://attack.mitre.org/techniques/T1547/012/) | Print Processors | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-34527](https://nvd.nist.gov/vuln/detail/CVE-2021-34527) | Windows Print Spooler Remote Code Execution Vulnerability | 9.0 |



</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=spoolsv.exe `process_rundll32` by Processes.dest Processes.user Processes.parent_process Processes.original_file_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `spoolsv_spawning_rundll32_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_rundll32](https://github.com/splunk/security_content/blob/develop/macros/process_rundll32.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **spoolsv_spawning_rundll32_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Limited false positives have been identified. There are limited instances where `rundll32.exe` may be spawned by a legitimate print driver.

#### Associated Analytic story
* [PrintNightmare CVE-2021-34527](/stories/printnightmare_cve-2021-34527)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | $parent_process$ has spawned $process_name$ on endpoint $ComputerName$. This behavior is suspicious and related to PrintNightmare. |


#### Reference

* [https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/](https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/)
* [https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/](https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/)
* [https://www.reddit.com/r/msp/comments/ob6y02/critical_vulnerability_printnightmare_exposes](https://www.reddit.com/r/msp/comments/ob6y02/critical_vulnerability_printnightmare_exposes)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/spoolsv_spawning_rundll32.yml) \| *version*: **2**