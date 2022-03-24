---
title: "Okta User Logins From Multiple Cities"
excerpt: "Valid Accounts
, Default Accounts
"
categories:
  - Application
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Default Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects logins from the same user from different cities in a 24 hour period.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk
- **ID**: 7594fa07-9f34-4d01-81cc-d6af6a5db9e8


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Default Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`okta` displayMessage="User login to Okta" client.geographicalContext.city!=null 
| stats min(_time) as firstTime max(_time) as lastTime dc(client.geographicalContext.city) as locations values(client.geographicalContext.city) as cities values(client.geographicalContext.state) as states by user 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `okta_user_logins_from_multiple_cities_filter` 
| search locations > 1
```

#### Macros
The SPL above uses the following Macros:
* [okta](https://github.com/splunk/security_content/blob/develop/macros/okta.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `okta_user_logins_from_multiple_cities_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* displayMessage
* client.geographicalContext.city
* client.geographicalContext.state
* user


#### How To Implement
This search is specific to Okta and requires Okta logs are being ingested in your Splunk deployment.

#### Known False Positives
Users in your enviornment may legitmately be travelling and loggin in from different locations. This search is useful for those users that should *not* be travelling for some reason, such as the COVID-19 pandemic. The search also relies on the geographical information being populated in the Okta logs. It is also possible that a connection from another region may be attributed to a login from a remote VPN endpoint.

#### Associated Analytic story
* [Suspicious Okta Activity](/stories/suspicious_okta_activity)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/okta_user_logins_from_multiple_cities.yml) \| *version*: **2**