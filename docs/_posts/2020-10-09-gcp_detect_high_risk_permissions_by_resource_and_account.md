---
title: "GCP Detect high risk permissions by resource and account"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of high risk permissions by resource and accounts. These are permissions that can allow attackers with compromised accounts to move laterally and escalate privileges.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-10-09
- **Author**: Rod Soto, Splunk
- **ID**: 2e70ef35-2187-431f-aedc-4503dc9b06ba


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`google_gcp_pubsub_message` data.protoPayload.authorizationInfo{}.permission=iam.serviceAccounts.getaccesstoken OR iam.serviceAccounts.setIamPolicy OR iam.serviceAccounts.actas OR dataflow.jobs.create OR composer.environments.create OR dataproc.clusters.create 
|table data.protoPayload.requestMetadata.callerIp data.protoPayload.authenticationInfo.principalEmail data.protoPayload.authorizationInfo{}.permission data.protoPayload.response.bindings{}.members{} data.resource.labels.project_id 
| `gcp_detect_high_risk_permissions_by_resource_and_account_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that `gcp_detect_high_risk_permissions_by_resource_and_account_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* data.protoPayload.authorizationInfo{}.permission
* data.protoPayload.requestMetadata.callerIp
* data.protoPayload.authenticationInfo.principalEmail
* data.protoPayload.authorizationInfo{}.permission
* data.protoPayload.response.bindings{}.members{}
* data.resource.labels.project_id


#### How To Implement
You must install splunk GCP add-on. This search works with gcp:pubsub:message logs

#### Known False Positives
High risk permissions are part of any GCP environment, however it is important to track resource and accounts usage, this search may produce false positives.

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
* [https://cloud.google.com/iam/docs/permissions-reference](https://cloud.google.com/iam/docs/permissions-reference)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/gcp_detect_high_risk_permissions_by_resource_and_account.yml) \| *version*: **1**