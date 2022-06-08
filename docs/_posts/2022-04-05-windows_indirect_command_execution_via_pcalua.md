---
title: "Windows Indirect Command Execution Via pcalua"
excerpt: "Indirect Command Execution
"
categories:
  - Endpoint
last_modified_at: 2022-04-05
toc: true
toc_label: ""
tags:
  - Indirect Command Execution
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic detects programs that have been started by pcalua.exe. pcalua.exe is the Microsoft Windows Program Compatability Assistant.  While this tool can be used to start legitimate programs, it has been observed being used to evade protections on command line execution.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-05
- **Author**: Eric McGinnis, Splunk
- **ID**: 3428ac18-a410-4823-816c-ce697d26f7a8


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1202](https://attack.mitre.org/techniques/T1202/) | Indirect Command Execution | Defense Evasion |

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

* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8
* CIS 10



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process="*pcalua* -a*" by Processes.dest Processes.user Processes.parent_process Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_path 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_indirect_command_execution_via_pcalua_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_indirect_command_execution_via_pcalua_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id
* Processes.process_path


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the full process path in the process field of CIM's Process data model. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where pcalua.exe may be used.

#### Known False Positives
Some legacy applications may be run using pcalua.exe.  Filter these results as needed.

#### Associated Analytic story
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | The Program Compatability Assistant (pcalua.exe) launched the process $process_name$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://twitter.com/KyleHanslovan/status/912659279806640128](https://twitter.com/KyleHanslovan/status/912659279806640128)
* [https://lolbas-project.github.io/lolbas/Binaries/Pcalua/](https://lolbas-project.github.io/lolbas/Binaries/Pcalua/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1202/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1202/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_indirect_command_execution_via_pcalua.yml) \| *version*: **1**