---
title: "Suspicious Powershell Command-Line Arguments"
excerpt: "PowerShell
"
categories:
  - Deprecated
last_modified_at: 2021-01-19
toc: true
toc_label: ""
tags:
  - PowerShell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for PowerShell processes started with a base64 encoded command-line passed to it, with parameters to modify the execution policy for the process, and those that prevent the display of an interactive prompt to the user. This combination of command-line options is suspicious because it overrides the default PowerShell execution policy, attempts to hide itself from the user, and passes an encoded script to be run on the command-line. Deprecated because almost the same as Malicious PowerShell Process - Encoded Command

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-19
- **Author**: David Dorsey, Splunk
- **ID**: 2cdb91d2-542c-497f-b252-be495e71f38c


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |

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
* CIS 7
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

| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=powershell.exe by Processes.user Processes.process_name Processes.parent_process_name Processes.dest  
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search (process=*-EncodedCommand* OR process=*-enc*) process=*-Exec* 
| `suspicious_powershell_command_line_arguments_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **suspicious_powershell_command-line_arguments_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model.

#### Known False Positives
Legitimate process can have this combination of command-line options, but it's not common.

#### Associated Analytic story
* [Malicious PowerShell](/stories/malicious_powershell)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/suspicious_powershell_command-line_arguments.yml) \| *version*: **6**