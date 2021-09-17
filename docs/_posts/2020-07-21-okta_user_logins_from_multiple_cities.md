---
title: "Okta User Logins From Multiple Cities"
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

This search detects logins from the same user from different cities in a 24 hour period.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |


#### Search

```
`okta` displayMessage="User login to Okta" client.geographicalContext.city!=null 
| stats min(_time) as firstTime max(_time) as lastTime dc(client.geographicalContext.city) as locations values(client.geographicalContext.city) as cities values(client.geographicalContext.state) as states by user 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `okta_user_logins_from_multiple_cities_filter` 
| search locations > 1
```

#### Associated Analytic Story
* [Suspicious Okta Activity](_stories/suspicious_okta_activity)


#### How To Implement
This search is specific to Okta and requires Okta logs are being ingested in your Splunk deployment.

#### Required field
* _time
* displayMessage
* client.geographicalContext.city
* client.geographicalContext.state
* user


#### Kill Chain Phase


#### Known False Positives
Users in your enviornment may legitmately be travelling and loggin in from different locations. This search is useful for those users that should *not* be travelling for some reason, such as the COVID-19 pandemic. The search also relies on the geographical information being populated in the Okta logs. It is also possible that a connection from another region may be attributed to a login from a remote VPN endpoint.




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 2