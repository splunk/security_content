---
title: "Okta Account Lockout Events"
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

Detect Okta user lockout events

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk
- **ID**: 62b70968-a0a5-4724-8ac4-67871e6f544d


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`okta` displayMessage="Max sign in attempts exceeded" 
| rename client.geographicalContext.country as country, client.geographicalContext.state as state, client.geographicalContext.city as city 
| table _time, user, country, state, city, src_ip 
| `okta_account_lockout_events_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [okta](https://github.com/splunk/security_content/blob/develop/macros/okta.yml)

Note that `okta_account_lockout_events_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* displayMessage
* client.geographicalContext.country
* client.geographicalContext.state
* client.geographicalContext.city


#### How To Implement
This search is specific to Okta and requires Okta logs are being ingested in your Splunk deployment.

#### Known False Positives
None. Account lockouts should be followed up on to determine if the actual user was the one who caused the lockout, or if it was an unauthorized actor.

#### Associated Analytic story
* [Suspicious Okta Activity](/stories/suspicious_okta_activity)


#### Kill Chain Phase




Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/okta_account_lockout_events.yml) \| *version*: **2**