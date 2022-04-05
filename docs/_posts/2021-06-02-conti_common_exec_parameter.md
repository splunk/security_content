---
title: "Conti Common Exec parameter"
excerpt: "User Execution
"
categories:
  - Endpoint
last_modified_at: 2021-06-02
toc: true
toc_label: ""
tags:
  - User Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects the suspicious commandline argument of revil ransomware to encrypt specific or all local drive and network shares of the compromised machine or host.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-06-02
- **Author**: Teoderick Contreras, Splunk
- **ID**: 624919bc-c382-11eb-adcc-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process = "*-m local*" OR Processes.process = "*-m net*" OR Processes.process = "*-m all*" OR Processes.process = "*-nomutex*" by Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.dest Processes.user Processes.process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `conti_common_exec_parameter_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **conti_common_exec_parameter_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
3rd party tool may have commandline parameter that can trigger this detection.

#### Associated Analytic story
* [Ransomware](/stories/ransomware)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ executing specific Conti Ransomware related parameters. |


#### Reference

* [https://malpedia.caad.fkie.fraunhofer.de/details/win.conti](https://malpedia.caad.fkie.fraunhofer.de/details/win.conti)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/inf1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/inf1/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/conti_common_exec_parameter.yml) \| *version*: **1**