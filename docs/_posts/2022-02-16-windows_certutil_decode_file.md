---
title: "Windows CertUtil Decode File"
excerpt: "Deobfuscate/Decode Files or Information"
categories:
  - Endpoint
last_modified_at: 2022-02-16
toc: true
toc_label: ""
tags:
  - Deobfuscate/Decode Files or Information
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

CertUtil.exe may be used to `encode` and `decode` a file, including PE and script code. Encoding will convert a file to base64 with `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` tags. Malicious usage will include decoding a encoded file that was downloaded. Once decoded, it will be loaded by a parallel process. Note that there are two additional command switches that may be used - `encodehex` and `decodehex`. Similarly, the file will be encoded in HEX and later decoded for further execution. During triage, identify the source of the file being decoded. Review its contents or execution behavior for further analysis.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-02-16
- **Author**: Michael Haag, Splunk
- **ID**: b06983f4-8f72-11ec-ab50-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | Defense Evasion |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Processes" IN(_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND process_name="certutil.exe" AND (like (cmd_line, "%decode%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_certutil_decode_file_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Typically seen used to `encode` files, but it is possible to see legitimate use of `decode`. Filter based on parent-child relationship, file paths, endpoint or user.

#### Associated Analytic story
* [Deobfuscate-Decode Files or Information](/stories/deobfuscate-decode_files_or_information)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$ attempting to decode a file on disk. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md)
* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
* [https://www.bleepingcomputer.com/news/security/certutilexe-could-allow-attackers-to-download-malware-while-bypassing-av/](https://www.bleepingcomputer.com/news/security/certutilexe-could-allow-attackers-to-download-malware-while-bypassing-av/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/ master/datasets/attack_techniques/T1140/atomic_red_team/encode-windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/ master/datasets/attack_techniques/T1140/atomic_red_team/encode-windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_certutil_decode_file.yml) \| *version*: **1**