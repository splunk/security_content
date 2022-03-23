---
title: "First time seen command line argument"
excerpt: "Command and Scripting Interpreter, Indirect Command Execution"
categories:
  - Endpoint
last_modified_at: 2021-11-30
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - Indirect Command Execution
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for command-line arguments that use a `/c` parameter to execute a command that has not previously been seen. This is an implementation on SPL2 of the rule `First time seen command line argument` by @bpatel. &#39;The following analytic identifies first time seen command-line arguments on a single endpoint. The analytic looks for arguments instantiated by `cmd.exe /c` and the associated command-line. Adversaries automate or spawn multiple processes using this method, this analytic may assist with identifying the first time it&#39;s been found on this endpoint.&#39;

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-11-30
- **Author**: Ignacio Bermudez Corrales, Splunk
- **ID**: fc0edc95-ff2b-48b0-9f6f-63da3789fd23


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1202](https://attack.mitre.org/techniques/T1202/) | Indirect Command Execution | Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| eval dest_user_id=ucast(map_get(input_event, "dest_user_id"), "string", null), dest_device_id=ucast(map_get(input_event, "dest_device_id"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), cmd_line=ucast(map_get(input_event, "process"), "string", null), cmd_line_norm=lower(cmd_line), cmd_line_norm=replace(cmd_line_norm, /[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/, "GUID"), cmd_line_norm=replace(cmd_line_norm, /(?<=\s)+\\[^:]*(?=\\.*\.\w{3}(\s
|$)+)/, "\\PATH"), /* replaces " \\Something\\Something\\command.ext" => "PATH\\command.ext" */ cmd_line_norm=replace(cmd_line_norm, /\w:\\[^:]*(?=\\.*\.\w{3}(\s
|$)+)/, "\\PATH"), /* replaces "C:\\Something\\Something\\command.ext" => "PATH\\command.ext" */ cmd_line_norm=replace(cmd_line_norm, /\d+/, "N"), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where process_name="cmd.exe" AND match_regex(ucast(cmd_line, "string", ""), /.* \/[cC] .*/)=true 
| select process_name, cmd_line, cmd_line_norm, timestamp, dest_device_id, dest_user_id 
| first_time_event input_columns=["cmd_line_norm"] 
| where first_time_cmd_line_norm 
| eval start_time = timestamp, end_time = timestamp, entities = mvappend(dest_device_id, dest_user_id), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `first_time_seen_command_line_argument_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* process_name
* _time
* dest_device_id
* dest_user_id
* process
* cmd_line


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Legitimate programs use command-line arguments to execute. Verify the command-line arguments to check what command/program is being executed. Filtering will be needed.

#### Associated Analytic story
* [Unusual Processes](/stories/unusual_processes)


#### Kill Chain Phase
* Command and Control
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 50 | 60 | A process $process_name$ ha been identified in the environment with a command-line $cmd_line$ not previously seen before on host $dest_device_id$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/first_time_seen_command_line_argument.yml) \| *version*: **4**