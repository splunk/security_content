---
title: "Suspicious File Write"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2019-04-25
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for files created with names that have been linked to malicious activity.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2019-04-25
- **Author**: Rico Valdez, Splunk
- **ID**: 57f76b8a-32f0-42ed-b358-d9fa3ca7bac8


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

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

| tstats `security_content_summariesonly` count values(Filesystem.action) as action values(Filesystem.file_path) as file_path min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem by Filesystem.file_name Filesystem.dest 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Filesystem)` 
| `suspicious_writes` 
| `suspicious_file_write_filter`
```

#### Macros
The SPL above uses the following Macros:
* [suspicious_writes](https://github.com/splunk/security_content/blob/develop/macros/suspicious_writes.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **suspicious_file_write_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must be ingesting data that records the filesystem activity from your hosts to populate the Endpoint file-system data model node. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or via other endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report file system reads and writes. In addition, this search leverages an included lookup file that contains the names of the files to watch for, as well as a note to communicate why that file name is being monitored. This lookup file can be edited to add or remove file the file names you want to monitor.

#### Known False Positives
It's possible for a legitimate file to be created with the same name as one noted in the lookup file. Filenames listed in the lookup file should be unique enough that collisions are rare. Looking at the location of the file and the process responsible for the activity can help determine whether or not the activity is legitimate.

#### Associated Analytic story
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/suspicious_file_write.yml) \| *version*: **3**