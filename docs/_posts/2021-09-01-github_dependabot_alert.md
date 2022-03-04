---
title: "GitHub Dependabot Alert"
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

This search looks for Dependabot Alerts in Github logs.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-09-01
- **Author**: Patrick Bareiss, Splunk
- **ID**: 05032b04-4469-4034-9df7-05f607d75cba


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | Compromise Software Dependencies and Development Tools | Initial Access |

| [T1195](https://attack.mitre.org/techniques/T1195/) | Supply Chain Compromise | Initial Access |

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

#### Macros
The SPL above uses the following Macros:
* [github](https://github.com/splunk/security_content/blob/develop/macros/github.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `github_dependabot_alert_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
You must index GitHub logs. You can follow the url in reference to onboard GitHub logs.

#### Known False Positives
unknown

#### Associated Analytic story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 30 | 90 | Vulnerabilities found in packages used by GitHub repository $repository$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.splunk.com/en_us/blog/tips-and-tricks/getting-github-data-with-webhooks.html](https://www.splunk.com/en_us/blog/tips-and-tricks/getting-github-data-with-webhooks.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/github_security_advisor_alert/github_security_advisor_alert.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/github_security_advisor_alert/github_security_advisor_alert.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/github_dependabot_alert.yml) \| *version*: **1**