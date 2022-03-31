---
title: "Excessive number of taskhost processes"
excerpt: "System Owner/User Discovery
"
categories:
  - Endpoint
last_modified_at: 2021-06-07
toc: true
toc_label: ""
tags:
  - System Owner/User Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This detection targets behaviors observed in post exploit kits like Meterpreter and Koadic that are run in memory.  We have observed that these tools must invoke an excessive number of taskhost.exe and taskhostex.exe processes to complete various actions (discovery, lateral movement, etc.).  It is extremely uncommon in the course of normal operations to see so many distinct taskhost and taskhostex processes running concurrently in a short time frame.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742)
- **Last Updated**: 2021-06-07
- **Author**: Michael Hart
- **ID**: f443dac2-c7cf-11eb-ab51-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Discovery |

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

| tstats `security_content_summariesonly` values(Processes.process_id) as process_ids  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.process_name = "taskhost.exe" OR Processes.process_name = "taskhostex.exe" BY Processes.dest Processes.process_name _time span=1h 
| `drop_dm_object_name(Processes)` 
| eval pid_count=mvcount(process_ids) 
| eval taskhost_count_=if(process_name == "taskhost.exe", pid_count, 0) 
| eval taskhostex_count_=if(process_name == "taskhostex.exe", pid_count, 0) 
| stats sum(taskhost_count_) as taskhost_count, sum(taskhostex_count_) as taskhostex_count by _time, dest, firstTime, lastTime 
| where taskhost_count > 10 and taskhostex_count > 10 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_number_of_taskhost_processes_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **excessive_number_of_taskhost_processes_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_id
* Processes.process_name
* Processes.dest
* Processes.user


#### How To Implement
To successfully implement this search you need to be ingesting events related to processes on the endpoints that include the name of the process and process id into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Administrators, administrative actions or certain applications may run many instances of taskhost and taskhostex concurrently.  Filter as needed.

#### Associated Analytic story
* [Meterpreter](/stories/meterpreter)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 80 | 70 | An excessive amount of $process_name$ was executed on $dest$ indicative of suspicious behavior. |


#### Reference

* [https://attack.mitre.org/software/S0250/](https://attack.mitre.org/software/S0250/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/meterpreter/taskhost_processes/logExcessiveTaskHost.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/meterpreter/taskhost_processes/logExcessiveTaskHost.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/excessive_number_of_taskhost_processes.yml) \| *version*: **1**