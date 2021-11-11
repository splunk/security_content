---
title: "Multiple Okta Users With Invalid Credentials From The Same IP"
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
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects Okta login failures due to bad credentials for multiple users originating from the same ip address.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk
- **ID**: 19cba45f-cad3-4032-8911-0c09e0444552


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`okta` outcome.reason=INVALID_CREDENTIALS 
| rename client.geographicalContext.country as country, client.geographicalContext.state as state, client.geographicalContext.city as city 
| stats min(_time) as firstTime max(_time) as lastTime dc(user) as distinct_users values(user) as users by src_ip, displayMessage, outcome.reason, country, state, city  
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
|  search distinct_users > 5
| `multiple_okta_users_with_invalid_credentials_from_the_same_ip_filter` 
```

#### Associated Analytic Story
* [Suspicious Okta Activity](/stories/suspicious_okta_activity)


#### How To Implement
This search is specific to Okta and requires Okta logs are being ingested in your Splunk deployment.

#### Required field
* _time
* outcome.reason
* client.geographicalContext.country
* client.geographicalContext.state
* client.geographicalContext.city
* user
* src_ip
* displayMessage


#### Kill Chain Phase


#### Known False Positives
A single public IP address servicing multiple legitmate users may trigger this search. In addition, the threshold of 5 distinct users may be too low for your needs. You may modify the included filter macro `multiple_okta_users_with_invalid_credentials_from_the_same_ip_filter` to raise the threshold or except specific IP adresses from triggering this search.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/multiple_okta_users_with_invalid_credentials_from_the_same_ip.yml) \| *version*: **2**