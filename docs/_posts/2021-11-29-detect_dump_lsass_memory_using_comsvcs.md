---
title: "Detect Dump LSASS Memory using comsvcs"
excerpt: "NTDS, OS Credential Dumping"
categories:
  - Endpoint
last_modified_at: 2021-11-29
toc: true
toc_label: ""
tags:
  - NTDS
  - Credential Access
  - OS Credential Dumping
  - Credential Access
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies credential dumping using comsvcs.dll with `regsvr32.exe`. This technique is common with adversaries who would like to dump the memory of lsass.exe and perform offline password cracking.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-11-29
- **Author**: Jose Hernandez, Splunk
- **ID**: 76bb9e35-f314-4c3d-a385-83c72a13ce4e


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | NTDS | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```

| from read_ssa_enriched_events() 
| eval tenant=ucast(map_get(input_event, "_tenant"), "string", null), machine=ucast(map_get(input_event, "dest_device_id"), "string", null), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), process=lower(ucast(map_get(input_event, "process"), "string", null)), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where process IS NOT NULL AND process_name IS NOT NULL AND process_name LIKE "%rundll32.exe%" AND match_regex(process, /(?i)comsvcs.dll[,\s]+MiniDump/)=true 
| eval start_time = timestamp, end_time = timestamp, entities = mvappend(machine), body=create_map(["event_id", event_id, "process_name", process_name, "process", process]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `detect_dump_lsass_memory_using_comsvcs_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* process_name
* _tenant
* _time
* dest_device_id
* process


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including Windows command line logging. You can see how we test this with [Event Code 4688](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688a) on the [attack_range](https://github.com/splunk/attack_range/blob/develop/ansible/roles/windows_common/tasks/windows-enable-4688-cmd-line-audit.yml).

#### Known False Positives
False positives should be limited, filter as needed.

#### Associated Analytic story
* [Credential Dumping](/stories/credential_dumping)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | A dump of lsass.exe was attempted using comsvcs.dll on endpoint $dest_device_id$ by user $dest_device_user$. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-3---dump-lsassexe-memory-using-comsvcsdll](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-3---dump-lsassexe-memory-using-comsvcsdll)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_dump_lsass_memory_using_comsvcs.yml) \| *version*: **2**