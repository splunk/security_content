---
title: "Okta Failed SSO Attempts"
excerpt: "Valid Accounts, Default Accounts"
categories:
  - Application
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Default Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect failed Okta SSO events

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk
- **ID**: 371a6545-2618-4032-ad84-93386b8698c5


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`okta` displayMessage="User attempted unauthorized access to app" 
| stats  min(_time) as firstTime max(_time) as lastTime values(app) as Apps count by user, result ,displayMessage, src_ip 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `okta_failed_sso_attempts_filter` 
```

#### Associated Analytic Story
* [Suspicious Okta Activity](/stories/suspicious_okta_activity)


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




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/okta_failed_sso_attempts.yml) \| *version*: **2**