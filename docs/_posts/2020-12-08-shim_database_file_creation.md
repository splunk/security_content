---
title: "Shim Database File Creation"
excerpt: "Application Shimming
, Event Triggered Execution
"
categories:
  - Endpoint
last_modified_at: 2020-12-08
toc: true
toc_label: ""
tags:
  - Application Shimming
  - Event Triggered Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for shim database files being written to default directories. The sdbinst.exe application is used to install shim database files (.sdb). According to Microsoft, a shim is a small library that transparently intercepts an API, changes the parameters passed, handles the operation itself, or redirects the operation elsewhere.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-12-08
- **Author**: David Dorsey, Splunk
- **ID**: 6e4c4588-ba2f-42fa-97e6-9f6f548eaa33


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1546.011](https://attack.mitre.org/techniques/T1546/011/) | Application Shimming | Persistence, Privilege Escalation |

| [T1546](https://attack.mitre.org/techniques/T1546/) | Event Triggered Execution | Persistence, Privilege Escalation |

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



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count values(Filesystem.action) values(Filesystem.file_hash) as file_hash values(Filesystem.file_path) as file_path  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_path=*Windows\\AppPatch\\Custom* by Filesystem.file_name Filesystem.dest 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
|`drop_dm_object_name(Filesystem)` 
| `shim_database_file_creation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **shim_database_file_creation_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.file_hash
* Filesystem.file_path
* Filesystem.file_name
* Filesystem.dest


#### How To Implement
You must be ingesting data that records the filesystem activity from your hosts to populate the Endpoint file-system data model node. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data.

#### Known False Positives
Because legitimate shim files are created and used all the time, this event, in itself, is not suspicious. However, if there are other correlating events, it may warrant further investigation.

#### Associated Analytic story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A process that possibly write shim database in $file_path$ in host $dest$ |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/shim_database_file_creation.yml) \| *version*: **3**