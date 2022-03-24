---
title: "Process Creating LNK file in Suspicious Location"
excerpt: "Phishing
, Spearphishing Link
"
categories:
  - Endpoint
last_modified_at: 2021-08-26
toc: true
toc_label: ""
tags:
  - Phishing
  - Spearphishing Link
  - Initial Access
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for a process launching an `*.lnk` file under `C:\User*` or `*\Local\Temp\*`. This is common behavior used by various spear phishing tools.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-08-26
- **Author**: Jose Hernandez, Splunk
- **ID**: 5d814af1-1041-47b5-a9ac-d754e82e9a26


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name="*.lnk" AND (Filesystem.file_path="C:\\User\\*" OR Filesystem.file_path="*\\Temp\\*") by _time span=1h Filesystem.process_guid Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.user 
| `drop_dm_object_name(Filesystem)` 
| rename process_guid as lnk_guid 
| join lnk_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name=* by _time span=1h Processes.parent_process_guid Processes.process_id Processes.process_name Processes.dest Processes.process_path Processes.process 
| `drop_dm_object_name(Processes)` 
| rename parent_process_guid as lnk_guid 
| fields _time lnk_guid process_id dest process_name process_path process] 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| table firstTime, lastTime, lnk_guid, process_id, user, dest, file_name, file_path, process_name, process, process_path, file_hash 
| `process_creating_lnk_file_in_suspicious_location_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `process_creating_lnk_file_in_suspicious_location_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.file_name
* Filesystem.file_path
* Filesystem.process_id
* Filesystem.file_name
* Filesystem.file_path
* Filesystem.file_hash
* Filesystem.user


#### How To Implement
You must be ingesting data that records filesystem and process activity from your hosts to populate the Endpoint data model. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or endpoint data sources, such as Sysmon.

#### Known False Positives
This detection should yield little or no false positive results. It is uncommon for LNK files to be executed from temporary or user directories.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)


#### Kill Chain Phase
* Installation
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A process $process_name$ that launching .lnk file in $file_path$ in host $dest$ |




#### Reference

* [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)
* [https://www.trendmicro.com/en_us/research/17/e/rising-trend-attackers-using-lnk-files-download-malware.html](https://www.trendmicro.com/en_us/research/17/e/rising-trend-attackers-using-lnk-files-download-malware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.002/lnk_file_temp_folder/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.002/lnk_file_temp_folder/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/process_creating_lnk_file_in_suspicious_location.yml) \| *version*: **5**