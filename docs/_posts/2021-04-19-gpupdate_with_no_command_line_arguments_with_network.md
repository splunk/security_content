---
title: "GPUpdate with no Command Line Arguments with Network"
excerpt: "Process Injection"
categories:
  - Endpoint
last_modified_at: 2021-04-19
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

The following analytic identifies gpupdate.exe with no command line arguments and with a network connection. It is unusual for gpupdate.exe to execute with no command line arguments present. This particular behavior is common with malicious software, including Cobalt Strike. During investigation, triage any network connections and parallel processes. Identify any suspicious module loads related to credential dumping or file writes. gpupdate.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-19
- **Author**: Michael Haag, Splunk
- **ID**: 2c853856-a140-11eb-a5b5-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name=gpupdate.exe by _time span=1h  Processes.process_guid Processes.process_name Processes.dest Processes.process_path Processes.process Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| regex process="(gpupdate\.exe.{0,4}$)" 
| join  process_guid [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Ports where Ports.dest_port !="0" by Ports.process_guid Ports.dest Ports.dest_port
| `drop_dm_object_name(Ports)` 
| rename  dest as connection_to_CNC] 
| table _time dest parent_process_name process_name process_path process process_guid connection_to_CNC dest_port 
| `gpupdate_with_no_command_line_arguments_with_network_filter`
```

#### Associated Analytic Story
* [Cobalt Strike](/stories/cobalt_strike)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* EventID
* process_name
* process_id
* parent_process_name
* dest_port
* process_path


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Limited false positives may be present in small environments. Tuning may be required based on parent process.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | Process gpupdate.exe  with parent_process $parent_process_name$ is executed on $dest$ by user $user$, followed by an outbound network connection to $connection_to_CNC$ on port $dest_port$. This behaviour is seen with cobaltstrike. |




#### Reference

* [https://raw.githubusercontent.com/xx0hcd/Malleable-C2-Profiles/0ef8cf4556e26f6d4190c56ba697c2159faa5822/crimeware/trick_ryuk.profile](https://raw.githubusercontent.com/xx0hcd/Malleable-C2-Profiles/0ef8cf4556e26f6d4190c56ba697c2159faa5822/crimeware/trick_ryuk.profile)
* [https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/](https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/gpupdate_with_no_command_line_arguments_with_network.yml) \| *version*: **1**