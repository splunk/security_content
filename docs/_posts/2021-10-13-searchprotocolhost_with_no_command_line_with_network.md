---
title: "SearchProtocolHost with no Command Line with Network"
excerpt: "Process Injection
"
categories:
  - Endpoint
last_modified_at: 2021-10-13
toc: true
toc_label: ""
tags:
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies searchprotocolhost.exe with no command line arguments and with a network connection. It is unusual for searchprotocolhost.exe to execute with no command line arguments present. This particular behavior is common with malicious software, including Cobalt Strike. During investigation, identify any network connections and parallel processes. Identify any suspicious module loads related to credential dumping or file writes. searchprotocolhost.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-13
- **Author**: Michael Haag, Splunk
- **ID**: b690df8c-a145-11eb-a38b-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name=searchprotocolhost.exe by _time span=1h  Processes.process_guid Processes.process_name Processes.dest Processes.process_path Processes.process Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| regex process="(searchprotocolhost\.exe.{0,4}$)" 
| join  process_guid [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Ports where Ports.dest_port !="0" by Ports.process_guid Ports.dest Ports.dest_port 
| `drop_dm_object_name(Ports)` 
| rename  dest as connection_to_CNC] 
| table _time dest parent_process_name process_name process_path process process_guid connection_to_CNC dest_port 
| `searchprotocolhost_with_no_command_line_with_network_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `searchprotocolhost_with_no_command_line_with_network_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* process_name
* process_id
* parent_process_name
* dest_port
* process_path


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `ports` node.

#### Known False Positives
Limited false positives may be present in small environments. Tuning may be required based on parent process.

#### Associated Analytic story
* [Cobalt Strike](/stories/cobalt_strike)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | A searchprotocolhost.exe process $process_name$ with no commandline in host $dest$ |




#### Reference

* [https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/SUSPICIOUS%20EXECUTION%20OF%20SEARCHPROTOCOLHOST%20(METHODOLOGY).ioc](https://github.com/fireeye/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/SUSPICIOUS%20EXECUTION%20OF%20SEARCHPROTOCOLHOST%20(METHODOLOGY).ioc)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon_searchprotocolhost.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon_searchprotocolhost.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/searchprotocolhost_with_no_command_line_with_network.yml) \| *version*: **2**