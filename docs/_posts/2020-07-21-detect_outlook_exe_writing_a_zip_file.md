---
title: "Detect Outlook exe writing a zip file"
excerpt: "Phishing
, Spearphishing Attachment
"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Phishing
  - Spearphishing Attachment
  - Initial Access
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for execution of process `outlook.exe` where the process is writing a `.zip` file to the disk.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: a51bfe1a-94f0-4822-b1e4-16ae10145893


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Installation
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

* CIS 7
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

| tstats `security_content_summariesonly`  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes where Processes.process_name=outlook.exe OR Processes.process_name=explorer.exe by _time span=5m Processes.parent_process_id Processes.process_id Processes.dest Processes.process_name Processes.parent_process_name Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| rename process_id as malicious_id
| rename parent_process_id as outlook_id
| join malicious_id type=inner[
| tstats `security_content_summariesonly` count values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name  FROM datamodel=Endpoint.Filesystem where (Filesystem.file_path=*zip*   OR Filesystem.file_name=*.lnk ) AND (Filesystem.file_path=C:\\Users* OR Filesystem.file_path=*Local\\Temp*) by  _time span=5m Filesystem.process_id Filesystem.file_hash Filesystem.dest  
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| rename process_id as malicious_id
| fields malicious_id outlook_id dest file_path file_name file_hash count file_id] 
| table firstTime lastTime user malicious_id outlook_id process_name parent_process_name file_name  file_path 
| where file_name != "" 
| `detect_outlook_exe_writing_a_zip_file_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_outlook_exe_writing_a_zip_file_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.parent_process_id
* Processes.process_id
* Processes.dest
* Processes.parent_process_name
* Processes.user


#### How To Implement
You must be ingesting data that records filesystem and process activity from your hosts to populate the Endpoint data model. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or endpoint data sources, such as Sysmon.

#### Known False Positives
It is not uncommon for outlook to write legitimate zip files to the disk.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/detect_outlook_exe_writing_a_zip_file.yml) \| *version*: **3**