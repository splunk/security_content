---
title: "Single Letter Process On Endpoint"
excerpt: "User Execution
, Malicious File
"
categories:
  - Endpoint
last_modified_at: 2020-12-08
toc: true
toc_label: ""
tags:
  - User Execution
  - Malicious File
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for process names that consist only of a single letter.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2020-12-08
- **Author**: David Dorsey, Splunk
- **ID**: a4214f0b-e01c-41bc-8cc4-d2b71e3056b4


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | Execution |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* ID.AM
* PR.DS



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 2



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes by Processes.dest, Processes.user, Processes.process, Processes.process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| eval process_name_length = len(process_name), endExe = if(substr(process_name, -4) == ".exe", 1, 0) 
| search process_name_length=5 AND endExe=1 
| table count, firstTime, lastTime, dest, user, process, process_name 
| `single_letter_process_on_endpoint_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **single_letter_process_on_endpoint_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.process
* Processes.process_name


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model.

#### Known False Positives
Single-letter executables are not always malicious. Investigate this activity with your normal incident-response process.

#### Associated Analytic story
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A suspicious process $process_name$ with single letter in host $dest$ |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.002/single_letter_exe/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.002/single_letter_exe/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/single_letter_process_on_endpoint.yml) \| *version*: **3**