---
title: "Email files written outside of the Outlook directory"
excerpt: "Email Collection, Local Email Collection"
categories:
  - Application
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Email Collection
  - Collection
  - Local Email Collection
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The search looks at the change-analysis data model and detects email files created outside the normal Outlook directory.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: ee18ed37-0802-4268-9435-b3b91aaa18xx


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Collection |

| [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | Local Email Collection | Collection |

#### Search

```

| tstats `security_content_summariesonly` count values(Filesystem.file_path) as file_path min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=*.pst OR Filesystem.file_name=*.ost) Filesystem.file_path != "C:\\Users\\*\\My Documents\\Outlook Files\\*"  Filesystem.file_path!="C:\\Users\\*\\AppData\\Local\\Microsoft\\Outlook*" by Filesystem.action Filesystem.process_id Filesystem.file_name Filesystem.dest 
| `drop_dm_object_name("Filesystem")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `email_files_written_outside_of_the_outlook_directory_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `email_files_written_outside_of_the_outlook_directory_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.file_path
* Filesystem.file_name
* Filesystem.action
* Filesystem.process_id
* Filesystem.dest


#### How To Implement
To successfully implement this search, you must be ingesting data that records the file-system activity from your hosts to populate the Endpoint.Filesystem data model node. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or by other endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report file-system reads and writes.

#### Known False Positives
Administrators and users sometimes prefer backing up their email data by moving the email files into a different folder. These attempts will be detected by the search.

#### Associated Analytic story
* [Collection and Staging](/stories/collection_and_staging)


#### Kill Chain Phase
* Actions on Objectives




Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/email_files_written_outside_of_the_outlook_directory.yml) \| *version*: **3**