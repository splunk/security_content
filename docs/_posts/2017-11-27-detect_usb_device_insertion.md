---
title: "Detect USB device insertion"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2017-11-27
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change_Analysis
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search is used to detect hosts that generate Windows Event ID 4663 for successful attempts to write to or read from a removable storage and Event ID 4656 for failures, which occurs when a USB drive is plugged in. In this scenario we are querying the Change_Analysis data model to look for Windows Event ID 4656 or 4663 where the priority of the affected host is marked as high in the ES Assets and Identity Framework.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change_Analysis](https://docs.splunk.com/Documentation/CIM/latest/User/ChangeAnalysis)

- **Last Updated**: 2017-11-27
- **Author**: Bhavin Patel, Splunk
- **ID**: 104658f4-afdc-499f-9719-17a43f9826f5

#### Search

```

| tstats `security_content_summariesonly` count earliest(_time) AS earliest latest(_time) AS latest from datamodel=Change_Analysis where (nodename = All_Changes) All_Changes.result="Removable Storage device" (All_Changes.result_id=4663 OR All_Changes.result_id=4656) (All_Changes.src_priority=high) by All_Changes.dest 
| `drop_dm_object_name("All_Changes")`
| `security_content_ctime(earliest)`
| `security_content_ctime(latest)`  
| `detect_usb_device_insertion_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_usb_device_insertion_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Changes.result
* All_Changes.result_id
* All_Changes.src_priority
* All_Changes.dest


#### How To Implement
To successfully implement this search, you must ingest Windows Security Event logs and track event code 4663 and 4656. Ensure that the field from the event logs is being mapped to the result_id field in the Change_Analysis data model. To minimize the alert volume, this search leverages the Assets and Identity framework to filter out events from those assets not marked high priority in the Enterprise Security Assets and Identity Framework.

#### Known False Positives
Legitimate USB activity will also be detected. Please verify and investigate as appropriate.

#### Associated Analytic story
* [Data Protection](/stories/data_protection)


#### Kill Chain Phase
* Installation
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_usb_device_insertion.yml) \| *version*: **1**