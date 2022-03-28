---
title: "Windows connhost exe started forcefully"
excerpt: "Windows Command Shell
"
categories:
  - Deprecated
last_modified_at: 2020-11-06
toc: true
toc_label: ""
tags:
  - Windows Command Shell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for the Console Window Host process (connhost.exe) executed using the force flag -ForceV1. This is not regular behavior in the Windows OS and is often seen executed by the Ryuk Ransomware. DEPRECATED This event is actually seen in the windows 10 client of attack_range_local. After further testing we realized this is not specific to Ryuk. 

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-11-06
- **Author**: Rod Soto, Jose Hernandez, Splunk
- **ID**: c114aaca-68ee-41c2-ad8c-32bf21db8769


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.process="*C:\\Windows\\system32\\conhost.exe* 0xffffffff *-ForceV1*" by Processes.user Processes.process_name Processes.process Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `windows_connhost_exe_started_forcefully_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `windows_connhost_exe_started_forcefully_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must be ingesting data that records the process-system activity from your hosts to populate the Endpoint Processes data-model object. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data.

#### Known False Positives
This process should not be ran forcefully, we have not see any false positives for this detection

#### Associated Analytic story
* [Ryuk Ransomware](/stories/ryuk_ransomware)


#### Kill Chain Phase
* Delivery



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/windows_connhost_exe_started_forcefully.yml) \| *version*: **1**