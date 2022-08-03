---
title: "Detect RClone Command-Line Usage"
excerpt: "Automated Exfiltration"
categories:
  - Endpoint
last_modified_at: 2021-12-03
toc: true
toc_label: ""
tags:
  - Automated Exfiltration
  - Exfiltration
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies commonly used command-line arguments used by `rclone.exe` to initiate a file transfer. Some arguments were negated as they are specific to the configuration used by adversaries. In particular, an adversary may list the files or directories of the remote file share using `ls` or `lsd`, which is not indicative of malicious behavior. During triage, at this stage of a ransomware event, exfiltration is about to occur or has already. Isolate the endpoint and continue investigating by review file modifications and parallel processes.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-12-03
- **Author**: Michael Haag, Splunk
- **ID**: e8b74268-5454-11ec-a799-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Exfiltration |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Processes" IN(_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND process_name="rclone.exe" AND (like (cmd_line, "%copy%") OR like (cmd_line, "%mega%")OR like (cmd_line, "%pcloud%") OR like (cmd_line, "%ftp%") OR like (cmd_line, "%--config%") OR like (cmd_line, "%--progress%") OR like (cmd_line, "%--no-check-certificate%") OR like (cmd_line, "%--ignore-existing%") OR like (cmd_line, "%--auto-confirm%") OR like (cmd_line, "%--transfers%") OR like (cmd_line, "%--multi-thread-streams%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `detect_rclone_command-line_usage_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint_Processess` datamodel.

#### Known False Positives
False positives should be limited as this is restricted to the Rclone process name. Filter or tune the analytic as needed.

#### Associated Analytic story
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exfiltration



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$ attempting to connect to a remote cloud service to move files or folders. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://redcanary.com/blog/rclone-mega-extortion/](https://redcanary.com/blog/rclone-mega-extortion/)
* [https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations](https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations)
* [https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)
* [https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1020/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_rclone_command-line_usage.yml) \| *version*: **1**