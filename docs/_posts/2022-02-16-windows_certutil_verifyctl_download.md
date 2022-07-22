---
title: "Windows CertUtil VerifyCtl Download"
excerpt: "Ingress Tool Transfer"
categories:
  - Endpoint
last_modified_at: 2022-02-16
toc: true
toc_label: ""
tags:
  - Ingress Tool Transfer
  - Command & Control
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Certutil.exe may download a file from a remote destination using `-VerifyCtl`. This behavior does require a URL to be passed on the command-line. In addition, `-f` (force) and `-split` (Split embedded ASN.1 elements, and save to files) will be used. It is not entirely common for `certutil.exe` to contact public IP space. \ During triage, capture any files on disk and review. Review the reputation of the remote IP or domain in question. Using `-VerifyCtl`, the file will either be written to the current working directory or `%APPDATA%\..\LocalLow\Microsoft\CryptnetUrlCache\Content\&lt;hash&gt;`. 

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-02-16
- **Author**: Michael Haag, Splunk
- **ID**: 9ac29c40-8f6b-11ec-b19a-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Processes" IN(_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND process_name="certutil.exe" AND (like (cmd_line, "%verifyctl%") AND like (cmd_line, "%split%")) OR (like (cmd_line, "%verifyctl%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_certutil_verifyctl_download_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Limited false positives in most environments, however tune as needed based on parent-child relationship or network connection.

#### Associated Analytic story
* [Ingress Tool Transfer](/stories/ingress_tool_transfer)
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$ attempting to download a file. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)
* [https://www.hexacorn.com/blog/2020/08/23/certutil-one-more-gui-lolbin/](https://www.hexacorn.com/blog/2020/08/23/certutil-one-more-gui-lolbin/)
* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732443(v=ws.11)#-verifyctl](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732443(v=ws.11)#-verifyctl)
* [https://www.avira.com/en/blog/certutil-abused-by-attackers-to-spread-threats](https://www.avira.com/en/blog/certutil-abused-by-attackers-to-spread-threats)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/T1105-windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/T1105-windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_certutil_verifyctl_download.yml) \| *version*: **1**