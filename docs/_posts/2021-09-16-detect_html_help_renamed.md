---
title: "Detect HTML Help Renamed"
excerpt: "Signed Binary Proxy Execution
, Compiled HTML File
"
categories:
  - Endpoint
last_modified_at: 2021-09-16
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Compiled HTML File
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a renamed instance of hh.exe (HTML Help) executing a Compiled HTML Help (CHM). This particular technique will load Windows script code from a compiled help file. CHM files may contain nearly any file type embedded, but only execute html/htm. Upon a successful execution, the following script engines may be used for execution - JScript, VBScript, VBScript.Encode, JScript.Encode, JScript.Compact. Analyst may identify vbscript.dll or jscript.dll loading into hh.exe upon execution. The "htm" and "html" file extensions were the only extensions observed to be supported for the execution of Shortcut commands or WSH script code. During investigation, identify script content origination. Validate it is the legitimate version of hh.exe by reviewing the PE metadata. hh.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-16
- **Author**: Michael Haag, Splunk
- **ID**: 62fed254-513b-460e-953d-79771493a9f3


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.001](https://attack.mitre.org/techniques/T1218/001/) | Compiled HTML File | Defense Evasion |

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

* PR.PT
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_hh` by Processes.dest Processes.user Processes.parent_process_name Processes.original_file_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_html_help_renamed_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_hh](https://github.com/splunk/security_content/blob/develop/macros/process_hh.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_html_help_renamed_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Although unlikely a renamed instance of hh.exe will be used legitimately, filter as needed.

#### Associated Analytic story
* [Suspicious Compiled HTML Activity](/stories/suspicious_compiled_html_activity)
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | The following $process_name$ has been identified as renamed, spawning from $parent_process_name$. |


#### Reference

* [https://attack.mitre.org/techniques/T1218/001/](https://attack.mitre.org/techniques/T1218/001/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Hh/](https://lolbas-project.github.io/lolbas/Binaries/Hh/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_html_help_renamed.yml) \| *version*: **3**