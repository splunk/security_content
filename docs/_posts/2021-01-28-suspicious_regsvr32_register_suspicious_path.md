---
title: "Suspicious Regsvr32 Register Suspicious Path"
excerpt: "System Binary Proxy Execution
, Regsvr32
"
categories:
  - Endpoint
last_modified_at: 2021-01-28
toc: true
toc_label: ""
tags:
  - System Binary Proxy Execution
  - Regsvr32
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may abuse Regsvr32.exe to proxy execution of malicious code by using non-standard file extensions to load malciious DLLs. Upon investigating, look for network connections to remote destinations (internal or external). Review additional parrallel processes and child processes for additional activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-01-28
- **Author**: Michael Haag, Splunk
- **ID**: 62732736-6250-11eb-ae93-0242ac130002


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | Defense Evasion |

| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | Defense Evasion |

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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8
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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_regsvr32` (Processes.process=*appdata* OR Processes.process=*programdata* OR Processes.process=*windows\temp*) (Processes.process!=*.dll Processes.process!=*.ax Processes.process!=*.ocx) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.original_file_name Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `suspicious_regsvr32_register_suspicious_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_regsvr32](https://github.com/splunk/security_content/blob/develop/macros/process_regsvr32.yml)

> :information_source:
> **suspicious_regsvr32_register_suspicious_path_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints, to populate the Endpoint data model in the Processes node. The command-line arguments are mapped to the "process" field in the Endpoint data model. Tune the query by filtering additional extensions found to be used by  legitimate processes. To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Limited false positives with the query restricted to specified paths. Add more world writeable paths as tuning continues.

#### Associated Analytic story
* [Suspicious Regsvr32 Activity](/stories/suspicious_regsvr32_activity)
* [Iceid](/stories/iceid)
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Suspicious $Processes.process_path.file_path$ process potentially loading malicious code |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1218/010/](https://attack.mitre.org/techniques/T1218/010/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
* [https://support.microsoft.com/en-us/topic/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages-a98d960a-7392-e6fe-d90a-3f4e0cb543e5](https://support.microsoft.com/en-us/topic/how-to-use-the-regsvr32-tool-and-troubleshoot-regsvr32-error-messages-a98d960a-7392-e6fe-d90a-3f4e0cb543e5)
* [https://any.run/report/f29a7d2ecd3585e1e4208e44bcc7156ab5388725f1d29d03e7699da0d4598e7c/0826458b-5367-45cf-b841-c95a33a01718](https://any.run/report/f29a7d2ecd3585e1e4208e44bcc7156ab5388725f1d29d03e7699da0d4598e7c/0826458b-5367-45cf-b841-c95a33a01718)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.010/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.010/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_regsvr32_register_suspicious_path.yml) \| *version*: **2**