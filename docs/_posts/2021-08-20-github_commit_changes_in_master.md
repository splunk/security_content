---
title: "Github Commit Changes In Master"
excerpt: "Trusted Relationship"
categories:
  - Cloud
last_modified_at: 2021-08-20
toc: true
tags:
  - Anomaly
  - T1199
  - Trusted Relationship
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a pushed or commit to master or main branch. This is to avoid unwanted modification to master without a review to the changes. Ideally in terms of devsecops the changes made in a branch and do a PR for review. of course in some cases admin of the project may did a changes directly to master branch

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-08-20
- **Author**: Teoderick Contreras, Splunk
- **ID**: c9d2bfe2-019f-11ec-a8eb-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1199](https://attack.mitre.org/techniques/T1199/) | Trusted Relationship | Initial Access |



#### Search

```
`github` branches{}.name = main OR branches{}.name = master 
| eval severity="low" 
| eval phase="code" 
|  stats count min(_time) as firstTime max(_time) as lastTime  by commit.author.html_url commit.commit.author.email commit.author.login commit.commit.message repository.pushed_at commit.commit.committer.date, phase, severity 
| eval phase="code" 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `github_commit_changes_in_master_filter`
```

#### Associated Analytic Story
* [DevSecOps](/stories/devsecops)


#### How To Implement
To successfully implement this search, you need to be ingesting logs related to github logs having the fork, commit, push metadata that can be use to monitor the changes in a github project.

#### Required field
* _time


#### Kill Chain Phase
* Exploitation


#### Known False Positives
admin can do changes directly to master branch



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | suspicious commit by $commit.commit.author.email$ to main branch |



#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1199/github_push_master/github_push_master.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1199/github_push_master/github_push_master.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/github_commit_changes_in_master.yml) \| *version*: **1**