---
title: "DLLHost with no Command Line Arguments with Network"
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

The following analytic identifies DLLHost.exe with no command line arguments with a network connection. It is unusual for DLLHost.exe to execute with no command line arguments present. This particular behavior is common with malicious software, including Cobalt Strike. During investigation, triage any network connections and parallel processes. Identify any suspicious module loads related to credential dumping or file writes. DLLHost.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-13
- **Author**: Michael Haag, Splunk
- **ID**: f1c07594-a141-11eb-8407-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name=dllhost.exe by _time span=1h  Processes.process_guid Processes.process_name Processes.dest Processes.process_path Processes.process Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| regex process="(dllhost\.exe.{0,4}$)" 
| join  process_guid [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Ports where Ports.dest_port !="0" by Ports.process_guid Ports.dest Ports.dest_port 
| `drop_dm_object_name(Ports)` 
| rename  dest as connection_to_CNC] 
| table _time dest parent_process_name process_name process_path process process_guid connection_to_CNC dest_port 
| `dllhost_with_no_command_line_arguments_with_network_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `dllhost_with_no_command_line_arguments_with_network_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventID
* process_name
* process_id
* parent_process_name
* dest_port
* process_path


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `port` node.

#### Known False Positives
Although unlikely, some legitimate third party applications may use a moved copy of dllhost, triggering a false positive.

#### Associated Analytic story
* [Cobalt Strike](/stories/cobalt_strike)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | The process $process_name$ was spawned by $parent_image$ without any command-line arguments on $dest$ by $user$. |




#### Reference

* [https://raw.githubusercontent.com/threatexpress/malleable-c2/c3385e481159a759f79b8acfe11acf240893b830/jquery-c2.4.2.profile](https://raw.githubusercontent.com/threatexpress/malleable-c2/c3385e481159a759f79b8acfe11acf240893b830/jquery-c2.4.2.profile)
* [https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/](https://blog.cobaltstrike.com/2021/02/09/learn-pipe-fitting-for-all-of-your-offense-projects/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon_dllhost.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon_dllhost.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/dllhost_with_no_command_line_arguments_with_network.yml) \| *version*: **2**