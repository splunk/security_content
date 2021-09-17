---
title: "Okta Failed SSO Attempts"
excerpt: "Default Accounts"
categories:
  - Application
last_modified_at: 2020-07-21
toc: true
tags:
  - Anomaly
  - T1078.001
  - Default Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Detect failed Okta SSO events

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |


#### Search

```
`okta` displayMessage="User attempted unauthorized access to app" 
| stats  min(_time) as firstTime max(_time) as lastTime values(app) as Apps count by user, result ,displayMessage, src_ip 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `okta_failed_sso_attempts_filter` 
```

#### Associated Analytic Story
* [Suspicious Okta Activity](_stories/suspicious_okta_activity)


#### How To Implement
This search is specific to Okta and requires Okta logs are being ingested in your Splunk deployment.

#### Required field
* _time
* displayMessage
* app
* user
* result
* src_ip


#### Kill Chain Phase


#### Known False Positives
There may be a faulty config preventing legitmate users from accessing apps they should have access to.




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 2