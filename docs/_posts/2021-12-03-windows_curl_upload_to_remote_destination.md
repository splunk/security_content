---
title: "Windows Curl Upload to Remote Destination"
excerpt: "Ingress Tool Transfer"
categories:
  - Endpoint
last_modified_at: 2021-12-03
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

The following analytic identifies the use of Windows Curl.exe uploading a file to a remote destination. \
`-T` or `--upload-file` is used when a file is to be uploaded to a remotge destination. \
`-d` or `--data` POST is the HTTP method that was invented to send data to a receiving web application, and it is, for example, how most common HTML forms on the web work. \
HTTP multipart formposts are done with `-F`, but this appears to not be compatible with the Windows version of Curl. Will update if identified adversary tradecraft. \
Adversaries may use one of the three methods based on the remote destination and what they are attempting to upload (zip vs txt). During triage, review parallel processes for further behavior. In addition, identify if the upload was successful in network logs. If a file was uploaded, isolate the endpoint and review.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-12-03
- **Author**: Michael Haag, Splunk
- **ID**: cc8d046a-543b-11ec-b864-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Processes" IN(_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null)

| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND process_name="curl.exe" AND (like (cmd_line, "%-T %") OR like (cmd_line, "%--upload-file %")OR like (cmd_line, "%-d %") OR like (cmd_line, "%--data %") OR like (cmd_line, "%-F %"))

| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `windows_curl_upload_to_remote_destination_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
False positives may be limited to source control applications and may be required to be filtered out.

#### Associated Analytic story
* [Ingress Tool Transfer](/stories/ingress_tool_transfer)


#### Kill Chain Phase
* Exfiltration



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$ uploading a file to a remote destination. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://everything.curl.dev/usingcurl/uploads](https://everything.curl.dev/usingcurl/uploads)
* [https://techcommunity.microsoft.com/t5/containers/tar-and-curl-come-to-windows/ba-p/382409](https://techcommunity.microsoft.com/t5/containers/tar-and-curl-come-to-windows/ba-p/382409)
* [https://twitter.com/d1r4c/status/1279042657508081664?s=20](https://twitter.com/d1r4c/status/1279042657508081664?s=20)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_curl_upload_to_remote_destination.yml) \| *version*: **1**