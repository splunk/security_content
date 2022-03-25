---
title: "Suspicious PlistBuddy Usage via OSquery"
excerpt: "Launch Agent
, Create or Modify System Process
"
categories:
  - Endpoint
last_modified_at: 2021-02-22
toc: true
toc_label: ""
tags:
  - Launch Agent
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
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

The following analytic identifies the use of a native MacOS utility, PlistBuddy, creating or modifying a properly list (.plist) file. In the instance of Silver Sparrow, the following commands were executed:\
- PlistBuddy -c "Add :Label string init_verx" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :RunAtLoad bool true" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :StartInterval integer 3600" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :ProgramArguments array" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :ProgramArguments:0 string /bin/sh" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :ProgramArguments:1 string -c" ~/Library/Launchagents/init_verx.plist \
Upon triage, capture the property list file being written to disk and review for further indicators. Contain the endpoint and triage further.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-02-22
- **Author**: Michael Haag, Splunk
- **ID**: 20ba6c32-c733-4a32-b64e-2688cf231399


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1543.001](https://attack.mitre.org/techniques/T1543/001/) | Launch Agent | Persistence, Privilege Escalation |

| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

#### Search

```
`osquery_process` "columns.cmdline"="*LaunchAgents*" OR "columns.cmdline"="*RunAtLoad*" OR "columns.cmdline"="*true*" 
|  `suspicious_plistbuddy_usage_via_osquery_filter`
```

#### Macros
The SPL above uses the following Macros:
* [osquery_process](https://github.com/splunk/security_content/blob/develop/macros/osquery_process.yml)

Note that `suspicious_plistbuddy_usage_via_osquery_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* columns.cmdline


#### How To Implement
OSQuery must be installed and configured to pick up process events (info at https://osquery.io) as well as using the Splunk OSQuery Add-on https://splunkbase.splunk.com/app/4402. Modify the macro and validate fields are correct.

#### Known False Positives
Some legitimate applications may use PlistBuddy to create or modify property lists and possibly generate false positives. Review the property list being modified or created to confirm.

#### Associated Analytic story
* [Silver Sparrow](/stories/silver_sparrow)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference

* [https://marcosantadev.com/manage-plist-files-plistbuddy/](https://marcosantadev.com/manage-plist-files-plistbuddy/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/suspicious_plistbuddy_usage_via_osquery.yml) \| *version*: **1**