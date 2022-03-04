---
title: "GCP Detect accounts with high risk roles by project"
excerpt: "Valid Accounts
"
categories:
  - Deprecated
last_modified_at: 2020-10-09
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of accounts with high risk roles by projects. Compromised accounts with high risk roles can move laterally or even scalate privileges at different projects depending on organization schema.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-10-09
- **Author**: Rod Soto, Splunk
- **ID**: 27af8c15-38b0-4408-b339-920170724adb


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`google_gcp_pubsub_message` data.protoPayload.request.policy.bindings{}.role=roles/owner OR roles/editor OR roles/iam.serviceAccountUser OR roles/iam.serviceAccountAdmin OR roles/iam.serviceAccountTokenCreator OR roles/dataflow.developer OR roles/dataflow.admin OR roles/composer.admin OR roles/dataproc.admin OR roles/dataproc.editor 
| table data.resource.type data.protoPayload.authenticationInfo.principalEmail data.protoPayload.authorizationInfo{}.permission data.protoPayload.authorizationInfo{}.resource data.protoPayload.response.bindings{}.role data.protoPayload.response.bindings{}.members{} 
| `gcp_detect_accounts_with_high_risk_roles_by_project_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that `gcp_detect_accounts_with_high_risk_roles_by_project_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* data.protoPayload.request.policy.bindings{}.role
* data.resource.type data.protoPayload.authenticationInfo.principalEmail
* data.protoPayload.authorizationInfo{}.permission
* data.protoPayload.authorizationInfo{}.resource
* data.protoPayload.response.bindings{}.role
* data.protoPayload.response.bindings{}.members{}


#### How To Implement
You must install splunk GCP add-on. This search works with gcp:pubsub:message logs

#### Known False Positives
Accounts with high risk roles should be reduced to the minimum number needed, however specific tasks and setups may be simply expected behavior within organization

#### Associated Analytic story
* [GCP Cross Account Activity](/stories/gcp_cross_account_activity)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference

* [https://github.com/dxa4481/gcploit](https://github.com/dxa4481/gcploit)
* [https://www.youtube.com/watch?v=Ml09R38jpok](https://www.youtube.com/watch?v=Ml09R38jpok)
* [https://cloud.google.com/iam/docs/understanding-roles](https://cloud.google.com/iam/docs/understanding-roles)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/gcp_detect_accounts_with_high_risk_roles_by_project.yml) \| *version*: **1**