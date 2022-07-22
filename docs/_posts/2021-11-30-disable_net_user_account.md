---
title: "Disable Net User Account"
excerpt: "Service Stop, Valid Accounts"
categories:
  - Endpoint
last_modified_at: 2021-11-30
toc: true
toc_label: ""
tags:
  - Service Stop
  - Impact
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify a suspicious command-line that disables a user account using the native `net.exe` or `net1.exe` utility to Windows. This technique may used by the adversaries to interrupt availability of accounts and continue the impact against the organization.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-11-30
- **Author**: Teoderick Contreras, Splunk
- **ID**: ba858b08-d26c-11eb-af9b-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1489](https://attack.mitre.org/techniques/T1489/) | Service Stop | Impact |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND like(cmd_line, "%/active:no%") AND like(cmd_line, "%user%") AND (process_name="net1.exe" OR process_name="net.exe") 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `disable_net_user_account_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed net.exe/net1.exe may be used.

#### Known False Positives
System administrators or automated scripts may disable an account but not a common practice. Filter as needed.

#### Associated Analytic story
* [XMRig](/stories/xmrig)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$ attempting to disable accounts. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/ssa_data1/net_user_dis.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/ssa_data1/net_user_dis.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disable_net_user_account.yml) \| *version*: **3**