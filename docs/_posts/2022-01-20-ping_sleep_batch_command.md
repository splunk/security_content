---
title: "Ping Sleep Batch Command"
excerpt: "Virtualization/Sandbox Evasion
, Time Based Evasion
"
categories:
  - Endpoint
last_modified_at: 2022-01-20
toc: true
toc_label: ""
tags:
  - Virtualization/Sandbox Evasion
  - Time Based Evasion
  - Defense Evasion
  - Discovery
  - Defense Evasion
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify the possible execution of ping sleep batch commands. This technique was seen in several malware samples and is used to trigger sleep times without explicitly calling sleep functions or commandlets. The goal is to delay the execution of malicious code and bypass detection or sandbox analysis. This  detection can be a good indicator of a process delaying its execution for malicious purposes.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-01-20
- **Author**: Teoderick Contreras, Splunk
- **ID**: ce058d6c-79f2-11ec-b476-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1497](https://attack.mitre.org/techniques/T1497/) | Virtualization/Sandbox Evasion | Defense Evasion, Discovery |

| [T1497.003](https://attack.mitre.org/techniques/T1497/003/) | Time Based Evasion | Defense Evasion, Discovery |

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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_ping` (Processes.parent_process = "*ping*" Processes.parent_process = *-n* Processes.parent_process="* Nul*"Processes.parent_process="*&gt;*") OR (Processes.process = "*ping*" Processes.process = *-n* Processes.process="* Nul*"Processes.process="*&gt;*") by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.process_guid Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `ping_sleep_batch_command_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_ping](https://github.com/splunk/security_content/blob/develop/macros/process_ping.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **ping_sleep_batch_command_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Administrator or network operator may execute this command. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [WhisperGate](/stories/whispergate)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | suspicious $process$ commandline run in $dest$ |


#### Reference

* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497.003/ping_sleep/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497.003/ping_sleep/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/ping_sleep_batch_command.yml) \| *version*: **1**