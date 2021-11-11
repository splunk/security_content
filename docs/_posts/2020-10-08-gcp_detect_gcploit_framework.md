---
title: "GCP Detect gcploit framework"
excerpt: "Valid Accounts"
categories:
  - Cloud
last_modified_at: 2020-10-08
toc: true
toc_label: ""
tags:
  - Valid Accounts
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

This search provides detection of GCPloit exploitation framework. This framework can be used to escalate privileges and move laterally from compromised high privilege accounts.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-10-08
- **Author**: Rod Soto, Splunk
- **ID**: a1c5a85e-a162-410c-a5d9-99ff639e5a52


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`google_gcp_pubsub_message` data.protoPayload.request.function.timeout=539s 
| table src src_user data.resource.labels.project_id data.protoPayload.request.function.serviceAccountEmail data.protoPayload.authorizationInfo{}.permission data.protoPayload.request.location http_user_agent 
| `gcp_detect_gcploit_framework_filter`
```

#### Associated Analytic Story
* [GCP Cross Account Activity](/stories/gcp_cross_account_activity)


#### How To Implement
You must install splunk GCP add-on. This search works with gcp:pubsub:message logs

#### Required field
* _time
* data.protoPayload.request.function.timeout
* src
* src_user
* data.resource.labels.project_id
* data.protoPayload.request.function.serviceAccountEmail
* data.protoPayload.authorizationInfo{}.permission
* data.protoPayload.request.location
* http_user_agent


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
Payload.request.function.timeout value can possibly be match with other functions or requests however the source user and target request account may indicate an attempt to move laterally accross acounts or projects





#### Reference

* [https://github.com/dxa4481/gcploit](https://github.com/dxa4481/gcploit)
* [https://www.youtube.com/watch?v=Ml09R38jpok](https://www.youtube.com/watch?v=Ml09R38jpok)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/gcp_detect_gcploit_framework.yml) \| *version*: **1**