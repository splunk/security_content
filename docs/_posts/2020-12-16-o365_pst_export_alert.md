---
title: "O365 PST export alert"
excerpt: "Email Collection"
categories:
  - Cloud
last_modified_at: 2020-12-16
toc: true
tags:
  - TTP
  - T1114
  - Email Collection
  - Collection
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objective
---

#### Description

This search detects when a user has performed an Ediscovery search or exported a PST file from the search. This PST file usually has sensitive information including email body content

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **Last Updated**: 2020-12-16
- **Author**: Rod Soto, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Collection |


#### Search

```
`o365_management_activity` Category=ThreatManagement Name="eDiscovery search started or exported" 
| stats count earliest(_time) as firstTime latest(_time) as lastTime by Source Severity AlertEntityId Operation Name 
|`security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `o365_pst_export_alert_filter`
```

#### Associated Analytic Story
* [Office 365 Detections](_stories/office_365_detections)
* [Data Exfiltration](_stories/data_exfiltration)


#### How To Implement
You must install splunk Microsoft Office 365 add-on. This search works with o365:management:activity

#### Required field
* _time
* Category
* Name
* Source
* Severity
* AlertEntityId
* Operation


#### Kill Chain Phase
* Actions on Objective


#### Known False Positives
PST export can be done for legitimate purposes but due to the sensitive nature of its content it must be monitored.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 48.0 | 80 | 60 |



#### Reference

* [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_export_pst_file/o365_export_pst_file.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_export_pst_file/o365_export_pst_file.json)


_version_: 1