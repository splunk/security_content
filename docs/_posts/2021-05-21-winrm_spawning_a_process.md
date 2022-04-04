---
title: "WinRM Spawning a Process"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Endpoint
last_modified_at: 2021-05-21
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-31166
  - Endpoint
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies suspicious processes spawning from WinRM (wsmprovhost.exe). This analytic is related to potential exploitation of CVE-2021-31166. which is a kernel-mode device driver http.sys vulnerability. Current proof of concept code will blue-screen the operating system. However, http.sys used by many different Windows processes, including WinRM. In this case, identifying suspicious process create (child processes) from `wsmprovhost.exe` is what this analytic is identifying.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-21
- **Author**: Drew Church, Michael Haag, Splunk
- **ID**: a081836a-ba4d-11eb-8593-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation
* Actions on Objectives


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
| [CVE-2021-31166](https://nvd.nist.gov/vuln/detail/CVE-2021-31166) | HTTP Protocol Stack Remote Code Execution Vulnerability | 7.5 |



</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=wsmprovhost.exe Processes.process_name IN ("cmd.exe","sh.exe","bash.exe","powershell.exe","pwsh.exe","schtasks.exe","certutil.exe","whoami.exe","bitsadmin.exe","scp.exe") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `winrm_spawning_a_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **winrm_spawning_a_process_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Unknown. Add new processes or filter as needed. It is possible system management software may spawn processes from `wsmprovhost.exe`.

#### Associated Analytic story
* [Unusual Processes](/stories/unusual_processes)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference

* [https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/win_susp_shell_spawn_from_winrm.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/win_susp_shell_spawn_from_winrm.yml)
* [https://www.zerodayinitiative.com/blog/2021/5/17/cve-2021-31166-a-wormable-code-execution-bug-in-httpsys](https://www.zerodayinitiative.com/blog/2021/5/17/cve-2021-31166-a-wormable-code-execution-bug-in-httpsys)
* [https://github.com/0vercl0k/CVE-2021-31166/blob/main/cve-2021-31166.py](https://github.com/0vercl0k/CVE-2021-31166/blob/main/cve-2021-31166.py)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/winrm_spawning_a_process.yml) \| *version*: **1**