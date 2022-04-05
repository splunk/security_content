---
title: "Office Product Spawn CMD Process"
excerpt: "Signed Binary Proxy Execution
, Mshta
"
categories:
  - Endpoint
last_modified_at: 2021-07-19
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Mshta
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

this search is to detect a suspicious office product process that spawn cmd child process. This is commonly seen in a ms office product having macro to execute shell command to download or execute malicious lolbin relative to its malicious code. This is seen in trickbot spear phishing doc where it execute shell cmd to run mshta payload.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-07-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: b8b19420-e892-11eb-9244-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | Defense Evasion |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name = "winword.exe" OR Processes.parent_process_name= "excel.exe" OR Processes.parent_process_name = "powerpnt.exe") `process_cmd` by Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.process_guid Processes.user Processes.dest Processes.original_file_name 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `office_product_spawn_cmd_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_cmd](https://github.com/splunk/security_content/blob/develop/macros/process_cmd.yml)

Note that **office_product_spawn_cmd_process_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
IT or network admin may create an document automation that will run shell script.

#### Associated Analytic story
* [Trickbot](/stories/trickbot)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | an office product parent process $parent_process_name$ spawn child process $process_name$ in host $dest$ |


#### Reference

* [https://twitter.com/cyb3rops/status/1416050325870587910?s=21](https://twitter.com/cyb3rops/status/1416050325870587910?s=21)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/spear_phish/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/spear_phish/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_product_spawn_cmd_process.yml) \| *version*: **2**