---
title: "Windows Command Shell DCRat ForkBomb Payload"
excerpt: "Windows Command Shell
, Command and Scripting Interpreter
"
categories:
  - Endpoint
last_modified_at: 2022-07-28
toc: true
toc_label: ""
tags:
  - Windows Command Shell
  - Command and Scripting Interpreter
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies DCRat "forkbomb" payload feature. This technique was seen in dark crystal RAT backdoor capabilities where it will execute several cmd child process executing "notepad.exe & pause". This analytic detects the multiple cmd.exe and child process notepad.exe  execution using batch script in the targeted host within 30s timeframe. this TTP can be a good pivot to check DCRat infection.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-07-28
- **Author**: Teoderick Contreras, Splunk
- **ID**: 2bb1a362-7aa8-444a-92ed-1987e8da83e1


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |

| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

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

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.parent_process_id) as parent_process_id values(Processes.process_id) as process_id dc(Processes.parent_process_id) as parent_process_id_count dc(Processes.process_id) as process_id_count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name= "cmd.exe" (Processes.process_name = "notepad.exe" OR Processes.original_file_name= "notepad.exe") Processes.parent_process = "*.bat*" by  Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.parent_process Processes.dest Processes.user  _time span=30s 
| where parent_process_id_count>= 10 AND process_id_count >=10 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_command_shell_dcrat_forkbomb_payload_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_command_shell_dcrat_forkbomb_payload_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
unknown

#### Associated Analytic story
* [DarkCrystal RAT](/stories/darkcrystal_rat)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | Multiple cmd.exe processes with child process of notepad.exe executed on $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://cert.gov.ua/article/405538](https://cert.gov.ua/article/405538)
* [https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat](https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat)
* [https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor](https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_forkbomb/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_forkbomb/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_command_shell_dcrat_forkbomb_payload.yml) \| *version*: **1**