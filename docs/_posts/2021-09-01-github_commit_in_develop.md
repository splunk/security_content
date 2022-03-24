---
title: "Github Commit In Develop"
excerpt: "Trusted Relationship
"
categories:
  - Cloud
last_modified_at: 2021-09-01
toc: true
toc_label: ""
tags:
  - Trusted Relationship
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a pushed or commit to develop branch. This is to avoid unwanted modification to develop without a review to the changes. Ideally in terms of devsecops the changes made in a branch and do a PR for review. of course in some cases admin of the project may did a changes directly to master branch

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-09-01
- **Author**: Teoderick Contreras, Splunk
- **ID**: f3030cb6-0b02-11ec-8f22-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1199](https://attack.mitre.org/techniques/T1199/) | Trusted Relationship | Initial Access |

#### Search

```
`github` branches{}.name = main OR branches{}.name = develop 
|  stats count min(_time) as firstTime max(_time) as lastTime  by commit.author.html_url commit.commit.author.email commit.author.login commit.commit.message repository.pushed_at commit.commit.committer.date 
| eval phase="code" 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `github_commit_in_develop_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [github](https://github.com/splunk/security_content/blob/develop/macros/github.yml)

Note that `github_commit_in_develop_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this search, you need to be ingesting logs related to github logs having the fork, commit, push metadata that can be use to monitor the changes in a github project.

#### Known False Positives
admin can do changes directly to develop branch

#### Associated Analytic story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | suspicious commit by $commit.commit.author.email$ to develop branch |




#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1199/github_push_master/github_push_develop.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1199/github_push_master/github_push_develop.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/github_commit_in_develop.yml) \| *version*: **1**