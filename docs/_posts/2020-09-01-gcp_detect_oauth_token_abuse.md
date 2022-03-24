---
title: "gcp detect oauth token abuse"
excerpt: "Valid Accounts
"
categories:
  - Deprecated
last_modified_at: 2020-09-01
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of possible GCP Oauth token abuse. GCP Oauth token without time limit can be exfiltrated and reused for keeping access sessions alive without further control of authentication, allowing attackers to access and move laterally.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-09-01
- **Author**: Rod Soto, Splunk
- **ID**: a7e9f7bb-8901-4ad0-8d88-0a4ab07b1972


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`google_gcp_pubsub_message` type.googleapis.com/google.cloud.audit.AuditLog 
|table protoPayload.@type protoPayload.status.details{}.@type protoPayload.status.details{}.violations{}.callerIp protoPayload.status.details{}.violations{}.type protoPayload.status.message  
| `gcp_detect_oauth_token_abuse_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that `gcp_detect_oauth_token_abuse_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install splunk GCP add-on. This search works with gcp:pubsub:message logs

#### Known False Positives
GCP Oauth token abuse detection will only work if there are access policies in place along with audit logs.

#### Associated Analytic story
* [GCP Cross Account Activity](/stories/gcp_cross_account_activity)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference

* [https://www.netskope.com/blog/gcp-oauth-token-hijacking-in-google-cloud-part-1](https://www.netskope.com/blog/gcp-oauth-token-hijacking-in-google-cloud-part-1)
* [https://www.netskope.com/blog/gcp-oauth-token-hijacking-in-google-cloud-part-2](https://www.netskope.com/blog/gcp-oauth-token-hijacking-in-google-cloud-part-2)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/gcp_detect_oauth_token_abuse.yml) \| *version*: **1**