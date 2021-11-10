---
title: "Circle CI Disable Security Job"
excerpt: "Compromise Client Software Binary"
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
  - Dev Sec Ops Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for disable security job in CircleCI pipeline.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-09-02
- **Author**: Patrick Bareiss, Splunk
- **ID**: 4a2fdd41-c578-4cd4-9ef7-980e352517f2


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
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

#### Associated Analytic Story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### How To Implement
You must index CircleCI logs.

#### Required field
* _times


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
unknown


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