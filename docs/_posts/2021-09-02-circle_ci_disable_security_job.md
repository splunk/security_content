---
title: "Circle CI Disable Security Job"
excerpt: "Compromise Client Software Binary
"
categories:
  - Cloud
last_modified_at: 2021-09-02
toc: true
toc_label: ""
tags:
  - Compromise Client Software Binary
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for disable security job in CircleCI pipeline.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-09-02
- **Author**: Patrick Bareiss, Splunk
- **ID**: 4a2fdd41-c578-4cd4-9ef7-980e352517f2


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1554](https://attack.mitre.org/techniques/T1554/) | Compromise Client Software Binary | Persistence |

#### Search

```
`circleci` 
| rename vcs.committer_name as user vcs.subject as commit_message vcs.url as url workflows.* as *  
| stats values(job_name) as job_names by workflow_id workflow_name user commit_message url branch 
| lookup mandatory_job_for_workflow workflow_name OUTPUTNEW job_name AS mandatory_job 
| search mandatory_job=* 
| eval mandatory_job_executed=if(like(job_names, "%".mandatory_job."%"), 1, 0) 
| where mandatory_job_executed=0 
| eval phase="build" 
| rex field=url "(?<repository>[^\/]*\/[^\/]*)$" 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `circle_ci_disable_security_job_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [circleci](https://github.com/splunk/security_content/blob/develop/macros/circleci.yml)

Note that `circle_ci_disable_security_job_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [mandatory_job_for_workflow](https://github.com/splunk/security_content/blob/develop/lookups/mandatory_job_for_workflow.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/mandatory_job_for_workflow.csv)

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
| 72.0 | 80 | 90 | disable security job $mandatory_job$ in workflow $workflow_name$ from user $user$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1554/circle_ci_disable_security_job/circle_ci_disable_security_job.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1554/circle_ci_disable_security_job/circle_ci_disable_security_job.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/circle_ci_disable_security_job.yml) \| *version*: **1**