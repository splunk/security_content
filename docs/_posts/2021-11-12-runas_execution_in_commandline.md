---
title: "Runas Execution in CommandLine"
excerpt: "Access Token Manipulation
, Token Impersonation/Theft
"
categories:
  - Endpoint
last_modified_at: 2021-11-12
toc: true
toc_label: ""
tags:
  - Access Token Manipulation
  - Token Impersonation/Theft
  - Defense Evasion
  - Privilege Escalation
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic look for a spawned runas.exe process with a administrator user option parameter. This parameter was abused by adversaries, malware author or even red teams to gain elevated privileges in target host. This is a good hunting query to figure out privilege escalation tactics that may used for different stages like lateral movement but take note that administrator may use this command in purpose so its better to see other event context before and after this analytic.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: 4807e716-43a4-11ec-a0e7-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1134](https://attack.mitre.org/techniques/T1134/) | Access Token Manipulation | Defense Evasion, Privilege Escalation |

| [T1134.001](https://attack.mitre.org/techniques/T1134/001/) | Token Impersonation/Theft | Defense Evasion, Privilege Escalation |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_runas` AND Processes.process = "*/user:*" AND Processes.process = "*admin*" by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `runas_execution_in_commandline_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_runas](https://github.com/splunk/security_content/blob/develop/macros/process_runas.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **runas_execution_in_commandline_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
A network operator or systems administrator may utilize an automated or manual execute this command that may generate false positives. filter is needed.

#### Associated Analytic story
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | elevated process using runas on $dest$ by $user$ |


#### Reference

* [https://app.any.run/tasks/ad4c3cda-41f2-4401-8dba-56cc2d245488/#](https://app.any.run/tasks/ad4c3cda-41f2-4401-8dba-56cc2d245488/#)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/runas_execution_in_commandline.yml) \| *version*: **1**