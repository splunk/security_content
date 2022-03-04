---
title: "Suspicious writes to System Volume Information"
excerpt: "Masquerading
"
categories:
  - Deprecated
last_modified_at: 2020-07-22
toc: true
toc_label: ""
tags:

  - Masquerading
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects writes to the 'System Volume Information' folder by something other than the System process.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-22
- **Author**: Rico Valdez, Splunk
- **ID**: cd6297cd-2bdd-4aa1-84aa-5d2f84228fac


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

#### Search

```
(`sysmon` OR tag=process) EventCode=11 process_id!=4 file_path=*System\ Volume\ Information* 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, Image, file_path 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `suspicious_writes_to_system_volume_information_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `suspicious_writes_to_system_volume_information_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You need to be ingesting logs with both the process name and command-line from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
It is possible that other utilities or system processes may legitimately write to this folder. Investigate and modify the search to include exceptions as appropriate.

#### Associated Analytic story
* [Collection and Staging](/stories/collection_and_staging)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/suspicious_writes_to_system_volume_information.yml) \| *version*: **2**