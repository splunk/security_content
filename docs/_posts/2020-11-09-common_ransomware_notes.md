---
title: "Common Ransomware Notes"
excerpt: "Data Destruction"
categories:
  - Endpoint
last_modified_at: 2020-11-09
toc: true
tags:
  - Hunting
  - T1485
  - Data Destruction
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for files created with names matching those typically used in ransomware notes that tell the victim how to get their data back.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-11-09
- **Author**: David Dorsey, Splunk
- **ID**: ada0f478-84a8-4641-a3f1-d82362d6bd71


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |



#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.dest) as dest values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem by Filesystem.file_name 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `ransomware_notes` 
| `common_ransomware_notes_filter`
```

#### Associated Analytic Story
* [SamSam Ransomware](/stories/samsam_ransomware)
* [Ransomware](/stories/ransomware)
* [Ryuk Ransomware](/stories/ryuk_ransomware)
* [Clop Ransomware](/stories/clop_ransomware)


#### How To Implement
You must be ingesting data that records file-system activity from your hosts to populate the Endpoint Filesystem data-model node. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or via other endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report file-system reads and writes.

#### Required field
* _time
* Filesystem.user
* Filesystem.dest
* Filesystem.file_path
* Filesystem.file_name


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
It&#39;s possible that a legitimate file could be created with the same name used by ransomware note files.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | A file - $file_name$ was written to disk on endpoint $dest$ by user $user$, this is indicative of a known ransomware note file and should be reviewed immediately. |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/ransomware_notes/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/ransomware_notes/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/common_ransomware_notes.yml) \| *version*: **4**