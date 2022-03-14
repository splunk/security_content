---
title: "Windows PowerShell Start-BitsTransfer"
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

Start-BitsTransfer is the PowerShell &#34;version&#34; of BitsAdmin.exe. Similar functionality is present. This technique variation is not as commonly used by adversaries, but has been abused in the past. Lesser known uses include the ability to set the `-TransferType` to `Upload` for exfiltration of files. In an instance where `Upload` is used, it is highly possible files will be archived. During triage, review parallel processes and process lineage. Capture any files on disk and review. For the remote domain or IP, what is the reputation?

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-02-16
- **Author**: Michael Haag, Splunk
- **ID**: 0bafd086-8f61-11ec-996e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1197](https://attack.mitre.org/techniques/T1197/) | BITS Jobs | Defense Evasion, Persistence |

| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=lower(ucast(map_get(input_event, "process"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL 
| where process_name="pwsh.exe" OR process_name="pwsh.exe" OR process_name="sqlps.exe" OR process_name="sqltoolsps.exe" OR process_name="powershell.exe" OR process_name="powershell_ise.exe" 
| where (like (cmd_line, "%start-bitstransfer%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_powershell_start-bitstransfer_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Limited false positives. It is possible administrators will utilize Start-BitsTransfer for administrative tasks, otherwise filter based parent process or command-line arguments.

#### Associated Analytic story
* [BITS Jobs](/stories/bits_jobs)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $dest_user_id$ attempting to download a file. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://isc.sans.edu/diary/Investigating+Microsoft+BITS+Activity/23281](https://isc.sans.edu/diary/Investigating+Microsoft+BITS+Activity/23281)
* [https://docs.microsoft.com/en-us/windows/win32/bits/using-windows-powershell-to-create-bits-transfer-jobs](https://docs.microsoft.com/en-us/windows/win32/bits/using-windows-powershell-to-create-bits-transfer-jobs)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/T1197_windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/T1197_windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_powershell_start-bitstransfer.yml) \| *version*: **1**