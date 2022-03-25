---
title: "Execute Javascript With Jscript COM CLSID"
excerpt: "Command and Scripting Interpreter
, Visual Basic
"
categories:
  - Endpoint
last_modified_at: 2021-06-22
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Visual Basic
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify suspicious process of cscript.exe where it tries to execute javascript using jscript.encode CLSID (COM OBJ). This technique was seen in ransomware (reddot ransomware) where it execute javascript with this com object with combination of amsi disabling technique.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-06-22
- **Author**: Teoderick Contreras, Splunk
- **ID**: dc64d064-d346-11eb-8588-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Visual Basic | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "cscript.exe" Processes.process="*-e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58}*" by Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process Processes.process_id Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `execute_javascript_with_jscript_com_clsid_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `execute_javascript_with_jscript_com_clsid_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.parent_process
* Processes.process_id
* Processes.dest
* Processes.user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the Filesystem responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesystem` node.

#### Known False Positives
unknown

#### Associated Analytic story
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 80 | 70 | Suspicious process of cscript.exe with a parent process $parent_process_name$ where it tries to execute javascript using jscript.encode CLSID (COM OBJ), detected on $dest$ by $user$ |




#### Reference

* [https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/](https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data2/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/execute_javascript_with_jscript_com_clsid.yml) \| *version*: **1**