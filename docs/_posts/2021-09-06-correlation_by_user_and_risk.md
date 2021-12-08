---
title: "Correlation by User and Risk"
excerpt: "Malicious Image, User Execution"
categories:
  - Cloud
last_modified_at: 2021-09-06
toc: true
toc_label: ""
tags:
  - Malicious Image
  - Execution
  - User Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search correlations detections by user and risk_score

- **Type**: Correlation
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-09-06
- **Author**: Patrick Bareiss, Splunk
- **ID**: 610e12dc-b6fa-4541-825e-4a0b3b6f6773


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1204.003](https://attack.mitre.org/techniques/T1204/003/) | Malicious Image | Execution |

| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

#### Search

```
`signals` 
| fillnull 
| stats sum(risk_score) as risk_score values(source) as signals values(repository) as repository by user 
| sort - risk_score 
| where risk_score > 80 
| `correlation_by_user_and_risk_filter`
```

#### Associated Analytic Story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### How To Implement
For Dev Sec Ops POC

#### Required field
* _time


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | Correlation triggered for user $user$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/correlation_by_user_and_risk.yml) \| *version*: **1**