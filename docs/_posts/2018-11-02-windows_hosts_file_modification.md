---
title: "Windows hosts file modification"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2018-11-02
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for modifications to the hosts file on all Windows endpoints across your environment.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2018-11-02
- **Author**: Rico Valdez, Splunk
- **ID**: 06a6fc63-a72d-41dc-8736-7e3dd9612116


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Command & Control


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.IP
* PR.PT
* PR.AC
* DE.AE
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 8
* CIS 12



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem  by Filesystem.file_name Filesystem.file_path Filesystem.dest 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| search Filesystem.file_name=hosts AND Filesystem.file_path=*Windows\\System32\\* 
| `drop_dm_object_name(Filesystem)` 
| `windows_hosts_file_modification_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **windows_hosts_file_modification_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this search, you must be ingesting data that records the file-system activity from your hosts to populate the Endpoint.Filesystem data model node. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or by other endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report file-system reads and writes.

#### Known False Positives
There may be legitimate reasons for system administrators to add entries to this file.

#### Associated Analytic story
* [Host Redirection](/stories/host_redirection)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/windows_hosts_file_modification.yml) \| *version*: **1**