---
title: "Detect Excessive User Account Lockouts"
excerpt: "Local Accounts"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
tags:
  - Anomaly
  - T1078.003
  - Local Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
---



#### Description

This search detects user accounts that have been locked out a relatively high number of times in a short period.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Local Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where nodename=All_Changes.Account_Management All_Changes.result="lockout" by All_Changes.user All_Changes.result 
|`drop_dm_object_name("All_Changes")` 
|`drop_dm_object_name("Account_Management")`
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| search count > 5 
| `detect_excessive_user_account_lockouts_filter`
```

#### Associated Analytic Story
* [Account Monitoring and Controls](_stories/account_monitoring_and_controls)


#### How To Implement
ou must ingest your Windows security event logs in the `Change` datamodel under the nodename is `Account_Management`, for this search to execute successfully. Please consider updating the cron schedule and the count of lockouts you want to monitor, according to your environment.

#### Required field
* _time
* All_Changes.result
* nodename
* All_Changes.user


#### Kill Chain Phase


#### Known False Positives
It is possible that a legitimate user is experiencing an issue causing multiple account login failures leading to lockouts.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 36.0 | 60 | 60 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-security.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-system.log)


_version_: 3