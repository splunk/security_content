---
title: "Correlation by Repository and Risk"
excerpt: "Malicious Image
, User Execution
"
categories:
  - Cloud
last_modified_at: 2021-09-06
toc: true
toc_label: ""
tags:
  - Malicious Image
  - User Execution
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search correlations detections by repository and risk_score

- **Type**: [Correlation](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-09-06
- **Author**: Patrick Bareiss, Splunk
- **ID**: 8da9fdd9-6a1b-4ae0-8a34-8c25e6be9687


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1204.003](https://attack.mitre.org/techniques/T1204/003/) | Malicious Image | Execution |

| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

#### Search

```
`signals` 
| fillnull 
| stats sum(risk_score) as risk_score values(source) as signals values(user) as user by repository 
| sort - risk_score 
| where risk_score > 80 
| `correlation_by_repository_and_risk_filter`
```

#### Macros
The SPL above uses the following Macros:
* [signals](https://github.com/splunk/security_content/blob/develop/macros/signals.yml)

Note that `correlation_by_repository_and_risk_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
For Dev Sec Ops POC

#### Known False Positives
unknown

#### Associated Analytic story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | Correlation triggered for user $user$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/correlation_by_repository_and_risk.yml) \| *version*: **1**