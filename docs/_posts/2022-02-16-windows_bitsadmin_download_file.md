---
title: "Windows Bitsadmin Download File"
excerpt: "BITS Jobs, Ingress Tool Transfer"
categories:
  - Endpoint
last_modified_at: 2022-02-16
toc: true
toc_label: ""
tags:
  - BITS Jobs
  - Defense Evasion
  - Persistence
  - Ingress Tool Transfer
  - Command & Control
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following query identifies Microsoft Background Intelligent Transfer Service utility `bitsadmin.exe` using the `transfer` parameter to download a remote object. In addition, look for `download` or `upload` on the command-line, the switches are not required to perform a transfer. Capture any files downloaded. Review the reputation of the IP or domain used. Typically once executed, a follow on command will be used to execute the dropped file. Note that the network connection or file modification events related will not spawn or create from `bitsadmin.exe`, but the artifacts will appear in a parallel process of `svchost.exe` with a command-line similar to `svchost.exe -k netsvcs -s BITS`. It&#39;s important to review all parallel and child processes to capture any behaviors and artifacts. In some suspicious and malicious instances, BITS jobs will be created. You can use `bitsadmin /list /verbose` to list out the jobs during investigation.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-02-16
- **Author**: Michael Haag, Splunk
- **ID**: d76e8188-8f5a-11ec-ace4-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1197](https://attack.mitre.org/techniques/T1197/) | BITS Jobs | Defense Evasion, Persistence |

| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Processes" IN(_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND process_name="bitsadmin.exe" AND (like (cmd_line, "%transfer%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_bitsadmin_download_file_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Limited false positives, however it may be required to filter based on parent process name or network connection.

#### Associated Analytic story
* [Ingress Tool Transfer](/stories/ingress_tool_transfer)
* [BITS Jobs](/stories/bits_jobs)
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $dest_user_id$ attempting to download a file. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/8eb52117b748d378325f7719554a896e37bccec7/atomics/T1105/T1105.md#atomic-test-9---windows---bitsadmin-bits-download](https://github.com/redcanaryco/atomic-red-team/blob/8eb52117b748d378325f7719554a896e37bccec7/atomics/T1105/T1105.md#atomic-test-9---windows---bitsadmin-bits-download)
* [https://github.com/redcanaryco/atomic-red-team/blob/bc705cb7aaa5f26f2d96585fac8e4c7052df0ff9/atomics/T1197/T1197.md](https://github.com/redcanaryco/atomic-red-team/blob/bc705cb7aaa5f26f2d96585fac8e4c7052df0ff9/atomics/T1197/T1197.md)
* [https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool](https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool)
* [https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/](https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/bits-windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/bits-windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_bitsadmin_download_file.yml) \| *version*: **1**