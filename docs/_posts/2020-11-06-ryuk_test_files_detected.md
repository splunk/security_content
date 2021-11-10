---
title: "Ryuk Test Files Detected"
excerpt: "Data Encrypted for Impact"
categories:
  - Endpoint
last_modified_at: 2020-11-06
toc: true
toc_label: ""
tags:
  - Data Encrypted for Impact
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for files that contain the key word *Ryuk* under any folder in the C drive, which is consistent with Ryuk propagation.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-11-06
- **Author**: Rod Soto, Jose Hernandez, Splunk
- **ID**: 57d44d70-28d9-4ed1-acf5-1c80ae2bbce3


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Impact |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem WHERE "Filesystem.file_path"=C:\\*Ryuk* BY "Filesystem.dest", "Filesystem.user", "Filesystem.file_path" 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `ryuk_test_files_detected_filter`
```

#### Associated Analytic Story
* [Ryuk Ransomware](/stories/ryuk_ransomware)


#### How To Implement
You must be ingesting data that records the filesystem activity from your hosts to populate the Endpoint Filesystem data-model object. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data.

#### Required field
* _time
* Filesystem.file_path
* Filesystem.dest
* Filesystem.user


#### Kill Chain Phase
* Delivery


#### Known False Positives
If there are files with this keywoord as file names it might trigger false possitives, please make use of our filters to tune out potential FPs.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | A creation of ryuk test file $file_path$ in host $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ryuk/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ryuk/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/ryuk_test_files_detected.yml) \| *version*: **1**