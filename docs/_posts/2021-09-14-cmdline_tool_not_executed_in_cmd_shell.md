---
title: "Cmdline Tool Not Executed In CMD Shell"
excerpt: "Command and Scripting Interpreter
, JavaScript
"
categories:
  - Endpoint
last_modified_at: 2021-09-14
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - JavaScript
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a non-standard parent process (not matching CMD, PowerShell, or Explorer) spawning `ipconfig.exe` or `systeminfo.exe`. This particular behavior was seen in FIN7's JSSLoader .NET payload. This is also typically seen when an adversary is injected into another process performing different discovery techniques. This event stands out as a TTP since these tools are commonly executed with a shell application or Explorer parent, and not by another application. This TTP is a good indicator for an adversary gathering host information, but one possible false positive might be an automated tool used by a system administator.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-09-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: 6c3f7dd8-153c-11ec-ac2d-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | JavaScript | Execution |

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


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where  (Processes.process_name = "ipconfig.exe" OR Processes.process_name = "systeminfo.exe") AND NOT (Processes.parent_process_name = "cmd.exe" OR Processes.parent_process_name = "powershell*" OR Processes.parent_process_name="pwsh.exe" OR Processes.parent_process_name = "explorer.exe") by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.original_file_name Processes.process_id Processes.process Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `cmdline_tool_not_executed_in_cmd_shell_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **cmdline_tool_not_executed_in_cmd_shell_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
A network operator or systems administrator may utilize an automated host discovery application that may generate false positives. Filter as needed.

#### Associated Analytic story
* [FIN7](/stories/fin7)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A non-standard parent process $parent_process_name$ spawned child process $process_name$ to execute command-line tool on $dest$. |


#### Reference

* [https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)
* [https://attack.mitre.org/groups/G0046/](https://attack.mitre.org/groups/G0046/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/jssloader/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/jssloader/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/cmdline_tool_not_executed_in_cmd_shell.yml) \| *version*: **1**