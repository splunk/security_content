---
title: "GitHub Pull Request from Unknown User"
excerpt: "Compromise Software Dependencies and Development Tools, Supply Chain Compromise"
categories:
  - Cloud
last_modified_at: 2021-09-01
toc: true
toc_label: ""
tags:
  - Compromise Software Dependencies and Development Tools
  - Initial Access
  - Supply Chain Compromise
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for Pull Request from unknown user.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-09-01
- **Author**: Patrick Bareiss, Splunk
- **ID**: 9d7b9100-8878-4404-914e-ca5e551a641e


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | Compromise Software Dependencies and Development Tools | Initial Access |

| [T1195](https://attack.mitre.org/techniques/T1195/) | Supply Chain Compromise | Initial Access |

#### Search

```
`github` check_suite.pull_requests{}.id=* 
| stats count by check_suite.head_commit.author.name repository.full_name check_suite.pull_requests{}.head.ref check_suite.head_commit.message 
| rename check_suite.head_commit.author.name as user repository.full_name as repository check_suite.pull_requests{}.head.ref as ref_head check_suite.head_commit.message as commit_message 
| search NOT `github_known_users` 
| eval phase="code" 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `github_pull_request_from_unknown_user_filter`
```

#### Associated Analytic Story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### How To Implement
You must index GitHub logs. You can follow the url in reference to onboard GitHub logs.

#### Required field
* _time
* alert.id
* repository.full_name
* repository.html_url
* action
* alert.affected_package_name
* alert.affected_range
* alert.created_at
* alert.external_identifier
* alert.external_reference
* alert.fixed_in
* alert.severity


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 30 | 90 | Vulnerabilities found in packages used by GitHub repository $repository$ |




#### Reference

* [https://www.splunk.com/en_us/blog/tips-and-tricks/getting-github-data-with-webhooks.html](https://www.splunk.com/en_us/blog/tips-and-tricks/getting-github-data-with-webhooks.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/github_pull_request/github_pull_request.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/github_pull_request/github_pull_request.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/github_pull_request_from_unknown_user.yml) \| *version*: **1**