---
title: "Detect Use of cmd exe to Launch Script Interpreters"
excerpt: "Command and Scripting Interpreter
, Windows Command Shell
"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Windows Command Shell
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the execution of the cscript.exe or wscript.exe processes, with a parent of cmd.exe. The search will return the count, the first and last time this execution was seen on a machine, the user, and the destination of the machine

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Mauricio Velazco, Splunk
- **ID**: b89919ed-fe5f-492c-b139-95dbb162039e


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |

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

| tstats `security_content_summariesonly` count values(Processes.process) min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="cmd.exe" (Processes.process_name=cscript.exe OR Processes.process_name =wscript.exe) by Processes.parent_process Processes.process_name Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
| `detect_use_of_cmd_exe_to_launch_script_interpreters_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_use_of_cmd_exe_to_launch_script_interpreters_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.parent_process_name
* Processes.process_name
* Processes.parent_process
* Processes.user
* Processes.dest


#### How To Implement
To successfully implement this search, you must be ingesting data that records process activity from your hosts to populate the endpoint data model in the processes node. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Some legitimate applications may exhibit this behavior.

#### Associated Analytic story
* [Emotet Malware  DHS Report TA18-201A ](/stories/emotet_malware__dhs_report_ta18-201a_)
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | cmd.exe launching script interpreters on $dest$ |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/cmd_spawns_cscript/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/cmd_spawns_cscript/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_use_of_cmd_exe_to_launch_script_interpreters.yml) \| *version*: **4**