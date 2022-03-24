---
title: "O365 PST export alert"
excerpt: "Email Collection
"
categories:
  - Cloud
last_modified_at: 2020-12-16
toc: true
toc_label: ""
tags:
  - Email Collection
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects when a user has performed an Ediscovery search or exported a PST file from the search. This PST file usually has sensitive information including email body content

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-12-16
- **Author**: Rod Soto, Splunk
- **ID**: 5f694cc4-a678-4a60-9410-bffca1b647dc


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Collection |

#### Search

```
`o365_management_activity` Category=ThreatManagement Name="eDiscovery search started or exported" 
| stats count earliest(_time) as firstTime latest(_time) as lastTime by Source Severity AlertEntityId Operation Name 
|`security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `o365_pst_export_alert_filter`
```

#### Macros
The SPL above uses the following Macros:
* [o365_management_activity](https://github.com/splunk/security_content/blob/develop/macros/o365_management_activity.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `o365_pst_export_alert_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Category
* Name
* Source
* Severity
* AlertEntityId
* Operation


#### How To Implement
You must install splunk Microsoft Office 365 add-on. This search works with o365:management:activity

#### Known False Positives
PST export can be done for legitimate purposes but due to the sensitive nature of its content it must be monitored.

#### Associated Analytic story
* [Office 365 Detections](/stories/office_365_detections)
* [Data Exfiltration](/stories/data_exfiltration)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 80 | 60 | User $Source$ has exported a PST file from the search using this operation- $Operation$ with a severity of $Severity$ |




#### Reference

* [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_export_pst_file/o365_export_pst_file.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_export_pst_file/o365_export_pst_file.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/o365_pst_export_alert.yml) \| *version*: **1**