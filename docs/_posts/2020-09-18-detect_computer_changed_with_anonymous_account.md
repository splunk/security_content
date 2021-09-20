---
title: "Detect Computer Changed with Anonymous Account"
excerpt: "Exploitation of Remote Services"
categories:
  - Endpoint
last_modified_at: 2020-09-18
toc: true
tags:
  - Hunting
  - T1210
  - Exploitation of Remote Services
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



#### Description

This search looks for Event Code 4742 (Computer Change) or EventCode 4624 (An account was successfully logged on) with an anonymous account.

- **ID**: 1400624a-d42d-484d-8843-e6753e6e3645
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-09-18
- **Author**: Rod Soto, Jose Hernandez, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services | Lateral Movement |


#### Search

```
`wineventlog_security` EventCode=4624 OR EventCode=4742 TargetUserName="ANONYMOUS LOGON" LogonType=3 
| stats count values(host) as host, values(TargetDomainName) as Domain, values(user) as user 
| `detect_computer_changed_with_anonymous_account_filter`
```

#### Associated Analytic Story
* [Detect Zerologon Attack](/stories/detect_zerologon_attack)


#### How To Implement
This search requires audit computer account management to be enabled on the system in order to generate Event ID 4742. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Event Logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

#### Required field
* _time
* EventCode
* TargetUserName
* LogonType
* TargetDomainName
* user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None thus far found



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 49.0 | 70 | 70 |



#### Reference

* [https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/](https://www.lares.com/blog/from-lares-labs-defensive-guidance-for-zerologon-cve-2020-1472/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1