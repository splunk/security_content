---
title: "Windows System Time Discovery W32tm Delay"
excerpt: "System Time Discovery
"
categories:
  - Endpoint
last_modified_at: 2022-07-28
toc: true
toc_label: ""
tags:
  - System Time Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies DCRat delay time tactics using w32tm. This technique was seen in DCRAT malware where it uses stripchart function of w32tm.exe application to delay the execution of its payload like c2 communication , beaconing and execution. This anomaly detection may help the analyst to check other possible event like the process who execute this command that may lead to DCRat attack.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-28
- **Author**: Teoderick Contreras, Splunk
- **ID**: b2cc69e7-11ba-42dc-a269-59c069a48870


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1124](https://attack.mitre.org/techniques/T1124/) | System Time Discovery | Discovery |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


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

| tstats `security_content_summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = w32tm.exe Processes.process= "* /stripchart *" Processes.process= "* /computer:localhost *" Processes.process= "* /period:*" Processes.process= "* /dataonly *" Processes.process= "* /samples:*" by  Processes.parent_process Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_system_time_discovery_w32tm_delay_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_system_time_discovery_w32tm_delay_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances of wermgr.exe may be used.

#### Known False Positives
unknown

#### Associated Analytic story
* [DarkCrystal RAT](/stories/darkcrystal_rat)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | Process name w32tm.exe is using suspcicious command line arguments $process$ on host $dest$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://cert.gov.ua/article/405538](https://cert.gov.ua/article/405538)
* [https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat](https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat)
* [https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor](https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_delay_execution/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_delay_execution/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_system_time_discovery_w32tm_delay.yml) \| *version*: **1**