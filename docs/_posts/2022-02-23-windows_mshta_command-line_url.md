---
title: "Windows MSHTA Command-Line URL"
excerpt: "Mshta, Signed Binary Proxy Execution"
categories:
  - Endpoint
last_modified_at: 2022-02-23
toc: true
toc_label: ""
tags:
  - Mshta
  - Defense Evasion
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies when Microsoft HTML Application Host (mshta.exe) utility is used to make remote http connections. Adversaries may use mshta.exe to proxy the download and execution of remote .hta files. The analytic identifies command line arguments of http and https being used. This technique is commonly used by malicious software to bypass preventative controls. The search will return the first time and last time these command-line arguments were used for these executions, as well as the target system, the user, process &#34;rundll32.exe&#34; and its parent process.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-02-23
- **Author**: Michael Haag, Splunk
- **ID**: 9b35c538-94ef-11ec-9439-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | Defense Evasion |

| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL 
| where process_name="mshta.exe" AND (like (cmd_line, "%http://%") OR like (cmd_line, "%https://%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_mshta_command-line_url_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest_device_id
* process_name
* parent_process_name
* process_path
* dest_user_id
* process
* cmd_line


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
It is possible legitimate applications may perform this behavior and will need to be filtered.

#### Associated Analytic story
* [Suspicious MSHTA Activity](/stories/suspicious_mshta_activity)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$ attempting to access a remote destination to download an additional payload. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://github.com/redcanaryco/AtomicTestHarnesses](https://github.com/redcanaryco/AtomicTestHarnesses)
* [https://redcanary.com/blog/introducing-atomictestharnesses/](https://redcanary.com/blog/introducing-atomictestharnesses/)
* [https://docs.microsoft.com/en-us/windows/win32/search/-search-3x-wds-extidx-prot-implementing](https://docs.microsoft.com/en-us/windows/win32/search/-search-3x-wds-extidx-prot-implementing)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_mshta_command-line_url.yml) \| *version*: **1**