---
title: "Cobalt Strike Named Pipes"
excerpt: "Process Injection
"
categories:
  - Endpoint
last_modified_at: 2021-02-22
toc: true
toc_label: ""
tags:
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of default or publicly known named pipes used with Cobalt Strike. A named pipe is a named, one-way or duplex pipe for communication between the pipe server and one or more pipe clients. Cobalt Strike uses named pipes in many ways and has default values used with the Artifact Kit and Malleable C2 Profiles. The following query assists with identifying these default named pipes. Each EDR product presents named pipes a little different. Consider taking the values and generating a query based on the product of choice. \
Upon triage, review the process performing the named pipe. If it is explorer.exe, It is possible it was injected into by another process. Review recent parallel processes to identify suspicious patterns or behaviors. A parallel process may have a network connection, review and follow the connection back to identify any file modifications.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-02-22
- **Author**: Michael Haag, Splunk
- **ID**: 5876d429-0240-4709-8b93-ea8330b411b5


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.PT
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`sysmon` EventID=17 OR EventID=18 PipeName IN (\\msagent_*, \\wkssvc*, \\DserNamePipe*, \\srvsvc_*, \\mojo.*, \\postex_*, \\status_*, \\MSSE-*, \\spoolss_*, \\win_svc*, \\ntsvcs*, \\winsock*, \\UIA_PIPE*) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, process_name, process_id process_path, PipeName 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `cobalt_strike_named_pipes_filter`
```

#### Macros
The SPL above uses the following Macros:
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **cobalt_strike_named_pipes_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventID
* PipeName
* Computer
* process_name
* process_path
* process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
The idea of using named pipes with Cobalt Strike is to blend in. Therefore, some of the named pipes identified and added may cause false positives. Filter by process name or pipe name to reduce false positives.

#### Associated Analytic story
* [Cobalt Strike](/stories/cobalt_strike)
* [Trickbot](/stories/trickbot)
* [DarkSide Ransomware](/stories/darkside_ransomware)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | An instance of $process_name$ was identified on endpoint $Computer$ by user $user$ accessing known suspicious named pipes related to Cobalt Strike. |


#### Reference

* [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)
* [https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
* [https://www.cobaltstrike.com/help-smb-beacon](https://www.cobaltstrike.com/help-smb-beacon)
* [https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/](https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/)
* [https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752](https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752)
* [https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html](https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/cobalt_strike_named_pipes.yml) \| *version*: **1**