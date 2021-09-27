---
title: "GitHub Dependabot Alert"
excerpt: "Compromise Software Dependencies and Development Tools"
categories:
  - Cloud
last_modified_at: 2021-09-01
toc: true
tags:
  - Anomaly
  - T1195.001
  - Compromise Software Dependencies and Development Tools
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for Dependabot Alerts in Github logs.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-09-01
- **Author**: Patrick Bareiss, Splunk
- **ID**: 05032b04-4469-4034-9df7-05f607d75cba


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | Compromise Software Dependencies and Development Tools | Initial Access |


#### Search

```
`github` alert.id=* action=create 
| rename repository.full_name as repository, repository.html_url as repository_url sender.login as user 
| stats min(_time) as firstTime max(_time) as lastTime by action alert.affected_package_name alert.affected_range alert.created_at alert.external_identifier alert.external_reference alert.fixed_in alert.severity repository repository_url user 
| eval phase="code" 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `github_dependabot_alert_filter`
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

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/github_security_advisor_alert/github_security_advisor_alert.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/github_security_advisor_alert/github_security_advisor_alert.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/github_dependabot_alert.yml) \| *version*: **1**