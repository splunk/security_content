---
title: "Short Lived Windows Accounts"
excerpt: "Local Account"
categories:
  - Endpoint
last_modified_at: 2020-07-06
toc: true
tags:
  - TTP
  - T1136.001
  - Local Account
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects accounts that were created and deleted in a short time period.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2020-07-06
- **Author**: David Dorsey, Splunk
- **ID**: b25f6f62-0782-43c1-b403-083231ffd97d


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Persistence |


#### Search

```

| tstats `security_content_summariesonly` values(All_Changes.result_id) as result_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.result_id=4720 OR All_Changes.result_id=4726 by _time span=4h All_Changes.user All_Changes.dest 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name("All_Changes")` 
| search result_id = 4720 result_id=4726 
| transaction user connected=false maxspan=240m 
| table firstTime lastTime count user dest result_id 
| `short_lived_windows_accounts_filter`
```

#### Associated Analytic Story
* [Account Monitoring and Controls](/stories/account_monitoring_and_controls)


#### How To Implement
This search requires you to have enabled your Group Management Audit Logs in your Local Windows Security Policy and be ingesting those logs.  More information on how to enable them can be found here: http://whatevernetworks.com/auditing-group-membership-changes-in-active-directory/

#### Required field
* _time
* All_Changes.result_id
* All_Changes.user
* All_Changes.dest


#### Kill Chain Phase


#### Known False Positives
It is possible that an administrator created and deleted an account in a short time period.  Verifying activity with an administrator is advised.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A user account created or delete shortly in host $dest$ |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-security.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-system.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/short_lived_windows_accounts.yml) \| *version*: **2**