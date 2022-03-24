---
title: "Detect Excessive Account Lockouts From Endpoint"
excerpt: "Valid Accounts
, Domain Accounts
"
categories:
  - Endpoint
last_modified_at: 2020-11-09
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Domain Accounts
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
  - Change
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search identifies endpoints that have caused a relatively high number of account lockouts in a short period.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)

- **Last Updated**: 2020-11-09
- **Author**: David Dorsey, Splunk
- **ID**: c026e3dd-7e18-4abb-8f41-929e836efe74


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management All_Changes.result="lockout" by All_Changes.dest All_Changes.result 
|`drop_dm_object_name("All_Changes")` 
|`drop_dm_object_name("Account_Management")`
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| search count > 5 
| `detect_excessive_account_lockouts_from_endpoint_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_excessive_account_lockouts_from_endpoint_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Changes.user
* nodename
* All_Changes.result
* All_Changes.dest


#### How To Implement
You must ingest your Windows security event logs in the `Change` datamodel under the nodename is `Account_Management`, for this search to execute successfully. Please consider updating the cron schedule and the count of lockouts you want to monitor, according to your environment. \
 **Splunk>Phantom Playbook Integration**\
If Splunk>Phantom is also configured in your environment, a Playbook called "Excessive Account Lockouts Enrichment and Response" can be configured to run when any results are found by this detection search. The Playbook executes the Contextual and Investigative searches in this Story, conducts additional information gathering on Windows endpoints, and takes a response action to shut down the affected endpoint. To use this integration, install the Phantom App for Splunk `https://splunkbase.splunk.com/app/3411/`, add the correct hostname to the "Phantom Instance" field in the Adaptive Response Actions when configuring this detection search, and set the corresponding Playbook to active. \
(Playbook Link:`https://my.phantom.us/4.1/playbook/excessive-account-lockouts-enrichment-and-response/`).\


#### Known False Positives
It's possible that a widely used system, such as a kiosk, could cause a large number of account lockouts.

#### Associated Analytic story
* [Account Monitoring and Controls](/stories/account_monitoring_and_controls)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | Multiple accounts have been locked out. Review $dest$ and results related to $user$. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-security.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-system.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_excessive_account_lockouts_from_endpoint.yml) \| *version*: **5**