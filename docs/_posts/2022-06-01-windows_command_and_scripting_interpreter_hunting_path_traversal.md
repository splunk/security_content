---
title: "Windows Command and Scripting Interpreter Hunting Path Traversal"
excerpt: "Command and Scripting Interpreter
"
categories:
  - Endpoint
last_modified_at: 2022-06-01
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies path traversal command-line execution and should be used to tune and driver other more higher fidelity analytics. This technique was seen in malicious document that execute malicious code using msdt.exe and path traversal technique that serve as defense evasion. This Hunting query is a good pivot to look for possible suspicious process and command-line that runs execute path traversal technique to run malicious code. This may help you to find possible downloaded malware or other lolbin execution.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-01
- **Author**: Teoderick Contreras, Michael Haag, Splunk
- **ID**: d0026380-b3c4-4da0-ac8e-02790063ff6b


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes  by Processes.original_file_name Processes.process_id Processes.parent_process_id Processes.process_hash Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| eval count_of_pattern1 = (mvcount(split(process,"/.."))-1) 
| eval count_of_pattern2 = (mvcount(split(process,"\.."))-1) 
| eval count_of_pattern3 = (mvcount(split(process,"\\.."))-1) 
| eval count_of_pattern4 = (mvcount(split(process,"//.."))-1) 
| search count_of_pattern1 > 1 OR count_of_pattern2 > 1 OR count_of_pattern3 > 1 OR count_of_pattern4 > 1 
| `windows_command_and_scripting_interpreter_hunting_path_traversal_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_command_and_scripting_interpreter_hunting_path_traversal_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product

#### Known False Positives
false positive may vary depends on the score you want to check. The bigger number of path traversal string count the better.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Microsoft Support Diagnostic Tool Vulnerability CVE-2022-30190](/stories/microsoft_support_diagnostic_tool_vulnerability_cve-2022-30190)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | A parent process $parent_process_name$ has spawned a child $process_name$ with path traversal commandline $process$ in $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/](https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/path_traversal/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/path_traversal/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_command_and_scripting_interpreter_hunting_path_traversal.yml) \| *version*: **1**