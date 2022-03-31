---
title: "Process Writing DynamicWrapperX"
excerpt: "Command and Scripting Interpreter
, Component Object Model
"
categories:
  - Endpoint
last_modified_at: 2021-10-05
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Component Object Model
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

DynamicWrapperX is an ActiveX component that can be used in a script to call Windows API functions, but it requires the dynwrapx.dll to be installed and registered. With that, a binary writing dynwrapx.dll to disk and registering it into the registry is highly suspect. Why is it needed? In most malicious instances, it will be written to disk at a non-standard location. During triage, review parallel processes and pivot on the process_guid. Review the registry for any suspicious modifications meant to load dynwrapx.dll. Identify any suspicious module loads of dynwrapx.dll. This will identify the process that will invoke vbs/wscript/cscript.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-05
- **Author**: Michael Haag, Splunk
- **ID**: b0a078e4-2601-11ec-9aec-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1559.001](https://attack.mitre.org/techniques/T1559/001/) | Component Object Model | Execution |

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

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time Processes.process_id Processes.process_name Processes.dest Processes.process_guid Processes.user 
| `drop_dm_object_name(Processes)` 
| join process_guid [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Filesystem where Filesystem.file_name="dynwrapx.dll" by _time Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.file_path Filesystem.process_guid Filesystem.user 
| `drop_dm_object_name(Filesystem)` 
| fields _time process_guid file_path file_name file_create_time user dest process_name] 
| stats count min(_time) as firstTime max(_time) as lastTime by dest process_name process_guid file_name file_path file_create_time user 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `process_writing_dynamicwrapperx_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **process_writing_dynamicwrapperx_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* process_name
* process_guid
* file_name
* file_path
* file_create_time user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Filesystem` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited, however it is possible to filter by Processes.process_name and specific processes (ex. wscript.exe). Filter as needed. This may need modification based on EDR telemetry and how it brings in registry data. For example, removal of (Default).

#### Associated Analytic story
* [Remcos](/stories/remcos)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $process_name$ was identified on endpoint $dest$ downloading the DynamicWrapperX dll. |


#### Reference

* [https://blog.f-secure.com/hunting-for-koadic-a-com-based-rootkit/](https://blog.f-secure.com/hunting-for-koadic-a-com-based-rootkit/)
* [https://www.script-coding.com/dynwrapx_eng.html](https://www.script-coding.com/dynwrapx_eng.html)
* [https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/)
* [https://tria.ge/210929-ap75vsddan](https://tria.ge/210929-ap75vsddan)
* [https://www.virustotal.com/gui/file/cb77b93150cb0f7fe65ce8a7e2a5781e727419451355a7736db84109fa215a89](https://www.virustotal.com/gui/file/cb77b93150cb0f7fe65ce8a7e2a5781e727419451355a7736db84109fa215a89)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/process_writing_dynamicwrapperx.yml) \| *version*: **1**