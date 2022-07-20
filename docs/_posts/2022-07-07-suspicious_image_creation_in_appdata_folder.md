---
title: "Suspicious Image Creation In Appdata Folder"
excerpt: "Screen Capture
"
categories:
  - Endpoint
last_modified_at: 2022-07-07
toc: true
toc_label: ""
tags:
  - Screen Capture
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious creation of image in appdata folder made by process that also has a file reference in appdata folder. This technique was seen in remcos rat that capture screenshot of the compromised machine and place it in the appdata and will be send to its C2 server. This TTP is really a good indicator to check that process because it is in suspicious folder path and image files are not commonly created by user in this folder path.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-07
- **Author**: Teoderick Contreras, Splunk
- **ID**: f6f904c4-1ac0-11ec-806b-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1113](https://attack.mitre.org/techniques/T1113/) | Screen Capture | Collection |

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

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name=*.exe Processes.process_path="*\\appdata\\Roaming\\*" by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("*.png","*.jpg","*.bmp","*.gif","*.tiff") Filesystem.file_path= "*\\appdata\\Roaming\\*" by _time span=1h Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.file_path Filesystem.process_guid 
| `drop_dm_object_name(Filesystem)` 
|rename process_guid as proc_guid 
| fields _time dest file_create_time file_name file_path process_name process_path process proc_guid] 
| `suspicious_image_creation_in_appdata_folder_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **suspicious_image_creation_in_appdata_folder_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* file_create_time
* file_name
* file_path
* process_name
* process_path
* process


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
unknown

#### Associated Analytic story
* [Remcos](/stories/remcos)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | process $process_name$ creating image file $file_path$ in $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://success.trendmicro.com/dcx/s/solution/1123281-remcos-malware-information?language=en_US](https://success.trendmicro.com/dcx/s/solution/1123281-remcos-malware-information?language=en_US)
* [https://blog.malwarebytes.com/threat-intelligence/2021/07/remcos-rat-delivered-via-visual-basic/](https://blog.malwarebytes.com/threat-intelligence/2021/07/remcos-rat-delivered-via-visual-basic/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_agent/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_agent/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_image_creation_in_appdata_folder.yml) \| *version*: **2**