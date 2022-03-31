---
title: "First time seen command line argument"
excerpt: "PowerShell
, Windows Command Shell
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - PowerShell
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

This search looks for command-line arguments that use a `/c` parameter to execute a command that has not previously been seen.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: a1b6e73f-98d5-470f-99ac-77aacd578473


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |

| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Command & Control
* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.PT
* DE.CM
* PR.IP



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
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

| tstats `security_content_summariesonly` min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = cmd.exe Processes.process = "* /c *" by Processes.process Processes.process_name Processes.parent_process_name Processes.dest
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| search [
| tstats `security_content_summariesonly` earliest(_time) as firstTime latest(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = cmd.exe Processes.process = "* /c *" by Processes.process 
| `drop_dm_object_name(Processes)` 
| inputlookup append=t previously_seen_cmd_line_arguments 
| stats min(firstTime) as firstTime, max(lastTime) as lastTime by process 
| outputlookup previously_seen_cmd_line_arguments 
| eval newCmdLineArgument=if(firstTime >= relative_time(now(), "-70m@m"), 1, 0) 
| where newCmdLineArgument=1 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| table process] 
| `first_time_seen_command_line_argument_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **first_time_seen_command_line_argument_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_cmd_line_arguments](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_cmd_line_arguments.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_cmd_line_arguments.csv)
* [previously_seen_cmd_line_arguments](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_cmd_line_arguments.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_cmd_line_arguments.csv)

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.dest


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must be ingesting logs with both the process name and command line from your endpoints. The complete process name with command-line arguments are mapped to the "process" field in the Endpoint data model. Please make sure you run the support search "Previously seen command line arguments,"&#151;which creates a lookup file called `previously_seen_cmd_line_arguments.csv`&#151;a historical baseline of all command-line arguments. You must also validate this list. For the search to do accurate calculation, ensure the search scheduling is the same value as the `relative_time` evaluation function.

#### Known False Positives
Legitimate programs can also use command-line arguments to execute. Please verify the command-line arguments to check what command/program is being executed. We recommend customizing the `first_time_seen_cmd_line_filter` macro to exclude legitimate parent_process_name

#### Associated Analytic story
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)
* [Orangeworm Attack Group](/stories/orangeworm_attack_group)
* [Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns](/stories/possible_backdoor_activity_associated_with_mudcarp_espionage_campaigns)
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/first_time_seen_command_line_argument.yml) \| *version*: **5**