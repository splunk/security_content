---
title: "Circle CI Disable Security Step"
excerpt: "Compromise Client Software Binary"
categories:
  - Cloud
last_modified_at: 2021-09-01
toc: true
toc_label: ""
tags:
  - Compromise Client Software Binary
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for disable security step in CircleCI pipeline.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-09-01
- **Author**: Patrick Bareiss, Splunk
- **ID**: 72cb9de9-e98b-4ac9-80b2-5331bba6ea97


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1554](https://attack.mitre.org/techniques/T1554/) | Compromise Client Software Binary | Persistence |

#### Search

```
`circleci` 
| rename workflows.job_id AS job_id 
| join job_id [ 
| search `circleci` 
| stats values(name) as step_names count by job_id job_name ] 
| stats count by step_names job_id job_name vcs.committer_name vcs.subject vcs.url owners{} 
| rename vcs.* as * , owners{} as user 
| lookup mandatory_step_for_job job_name OUTPUTNEW step_name AS mandatory_step 
| search mandatory_step=* 
| eval mandatory_step_executed=if(like(step_names, "%".mandatory_step."%"), 1, 0) 
| where mandatory_step_executed=0 
| rex field=url "(?<repository>[^\/]*\/[^\/]*)$" 
| eval phase="build"  
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `circle_ci_disable_security_step_filter`
```

#### Macros
The SPL above uses the following Macros:
* [circleci](https://github.com/splunk/security_content/blob/develop/macros/circleci.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `circle_ci_disable_security_step_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [mandatory_step_for_job](https://github.com/splunk/security_content/blob/develop/lookups/mandatory_step_for_job.yml) with [data](https://github.com/splunk/security_content/blob/develop/lookups/mandatory_step_for_job.csv)

#### Required field
* _times


#### How To Implement
You must index CircleCI logs.

#### Known False Positives
unknown

#### Associated Analytic story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | disable security step $mandatory_step$ in job $job_name$ from user $user$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1554/circle_ci_disable_security_step/circle_ci_disable_security_step.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1554/circle_ci_disable_security_step/circle_ci_disable_security_step.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/circle_ci_disable_security_step.yml) \| *version*: **1**