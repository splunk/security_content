---
title: "Remcos RAT File Creation in Remcos Folder"
excerpt: "Screen Capture
"
categories:
  - Endpoint
last_modified_at: 2021-09-21
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect file creation in remcos folder in appdata which is the keylog and clipboard logs that will be send to its c2 server. This is really a good TTP indicator that there is a remcos rat in the system that do keylogging, clipboard grabbing and audio recording.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 25ae862a-1ac3-11ec-94a1-acde48001122


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

|tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("*.dat") Filesystem.file_path = "*\\remcos\\*" by _time Filesystem.file_name Filesystem.file_path Filesystem.dest Filesystem.file_create_time 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `remcos_rat_file_creation_in_remcos_folder_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **remcos_rat_file_creation_in_remcos_folder_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* file_create_time
* file_name
* file_path


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
unknown

#### Associated Analytic story
* [Remcos](/stories/remcos)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 100.0 | 100 | 100 | file $file_name$ created in $file_path$ of $dest$ |


#### Reference

* [https://success.trendmicro.com/solution/1123281-remcos-malware-information](https://success.trendmicro.com/solution/1123281-remcos-malware-information)
* [https://blog.malwarebytes.com/threat-intelligence/2021/07/remcos-rat-delivered-via-visual-basic/](https://blog.malwarebytes.com/threat-intelligence/2021/07/remcos-rat-delivered-via-visual-basic/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_agent/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_agent/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/remcos_rat_file_creation_in_remcos_folder.yml) \| *version*: **1**