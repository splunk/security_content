---
title: "Hiding Files And Directories With Attrib exe"
excerpt: "Windows File and Directory Permissions Modification, File and Directory Permissions Modification"
categories:
  - Endpoint
last_modified_at: 2021-12-20
toc: true
toc_label: ""
tags:
  - Windows File and Directory Permissions Modification
  - Defense Evasion
  - File and Directory Permissions Modification
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Attackers leverage an existing Windows binary, attrib.exe, to mark specific as hidden by using specific flags so that the victim does not see the file.  The search looks for specific command-line arguments to detect the use of attrib.exe to hide files.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-12-20
- **Author**: Teoderick Contreras, Splunk
- **ID**: 028e4406-6176-11ec-aec2-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1222.001](https://attack.mitre.org/techniques/T1222/001/) | Windows File and Directory Permissions Modification | Defense Evasion |

| [T1222](https://attack.mitre.org/techniques/T1222/) | File and Directory Permissions Modification | Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND match_regex(cmd_line, /\+h/)=true AND process_name="attrib.exe" 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `hiding_files_and_directories_with_attrib_exe_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Known False Positives
Some applications and users may legitimately use attrib.exe to interact with the files. 

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Information Sabotage](/stories/information_sabotage)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | Attrib.exe with +h flag to hide files on $dest$ executed by $user$ is detected. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/attrib](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/attrib)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/attrib_hidden/security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/attrib_hidden/security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/hiding_files_and_directories_with_attrib_exe.yml) \| *version*: **1**