---
title: "Windows Bits Job Persistence"
excerpt: "BITS Jobs"
categories:
  - Endpoint
last_modified_at: 2022-02-15
toc: true
toc_label: ""
tags:
  - BITS Jobs
  - Defense Evasion
  - Persistence
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following query identifies Microsoft Background Intelligent Transfer Service utility `bitsadmin.exe` scheduling a BITS job to persist on an endpoint. The query identifies the parameters used to create, resume or add a file to a BITS job. Typically seen combined in a oneliner or ran in sequence. If identified, review the BITS job created and capture any files written to disk. It is possible for BITS to be used to upload files and this may require further network data analysis to identify. You can use `bitsadmin /list /verbose` to list out the jobs during investigation.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-02-15
- **Author**: Michael Haag, Splunk
- **ID**: 1e25e97a-8ea4-11ec-9767-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1197](https://attack.mitre.org/techniques/T1197/) | BITS Jobs | Defense Evasion, Persistence |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Processes" IN(_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND process_name="bitsadmin.exe" AND (like (cmd_line, "%create%") OR like (cmd_line, "%addfile%")OR like (cmd_line, "%setnotifyflags%") OR like (cmd_line, "%setnotifycmdline%") OR like (cmd_line, "%setminretrydelay%") OR like (cmd_line, "%setcustomheaders%") OR like (cmd_line, "%resume%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_bits_job_persistence_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Limited false positives will be present. Typically, applications will use `BitsAdmin.exe`. Any filtering should be done based on command-line arguments (legitimate applications) or parent process.

#### Associated Analytic story
* [BITS Jobs](/stories/bits_jobs)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $dest_user_id$ attempting to persist using BITS. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)
* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md#atomic-test-3---persist-download--execute](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md#atomic-test-3---persist-download--execute)
* [https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/bits-windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/bits-windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_bits_job_persistence.yml) \| *version*: **1**