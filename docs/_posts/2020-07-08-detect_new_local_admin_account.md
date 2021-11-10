---
title: "Detect New Local Admin account"
excerpt: "Local Account, Create Account"
categories:
  - Endpoint
last_modified_at: 2020-07-08
toc: true
toc_label: ""
tags:
  - Local Account
  - Persistence
  - Create Account
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for newly created accounts that have been elevated to local administrators.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-08
- **Author**: David Dorsey, Splunk
- **ID**: b25f6f62-0712-43c1-b203-083231ffd97d


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Persistence |

| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Persistence |

#### Search

```
`wineventlog_security` EventCode=4720 OR (EventCode=4732 Group_Name=Administrators) 
| transaction member_id connected=false maxspan=180m 
| rename member_id as user 
| stats count min(_time) as firstTime max(_time) as lastTime by user dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_new_local_admin_account_filter`
```

#### Associated Analytic Story
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)
* [HAFNIUM Group](/stories/hafnium_group)


#### How To Implement
You must be ingesting Windows event logs using the Splunk Windows TA and collecting event code 4720 and 4732

#### Required field
* _time
* EventCode
* Group_Name
* member_id
* dest
* user


#### Kill Chain Phase
* Actions on Objectives
* Command and Control


#### Known False Positives
The activity may be legitimate. For this reason, it&#39;s best to verify the account with an administrator and ask whether there was a valid service request for the account creation. If your local administrator group name is not &#34;Administrators&#34;, this search may generate an excessive number of false positives


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | A $user$ on $dest$ was added recently. Identify if this was legitimate behavior or not. |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-security.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-system.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_new_local_admin_account.yml) \| *version*: **2**