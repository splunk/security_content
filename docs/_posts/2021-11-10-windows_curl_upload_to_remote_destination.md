---
title: "Windows Curl Upload to Remote Destination"
excerpt: "Ingress Tool Transfer"
categories:
  - Endpoint
last_modified_at: 2021-11-10
toc: true
toc_label: ""
tags:
  - Ingress Tool Transfer
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of Windows Curl.exe uploading a file to a remote destination. \
`-T` or `--upload-file` is used when a file is to be uploaded to a remotge destination. \
`-d` or `--data` POST is the HTTP method that was invented to send data to a receiving web application, and it is, for example, how most common HTML forms on the web work. \
HTTP multipart formposts are done with `-F`, but this appears to not be compatible with the Windows version of Curl. Will update if identified adversary tradecraft. \
Adversaries may use one of the three methods based on the remote destination and what they are attempting to upload (zip vs txt). During triage, review parallel processes for further behavior. In addition, identify if the upload was successful in network logs. If a file was uploaded, isolate the endpoint and review.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-10
- **Author**: Michael Haag, Splunk
- **ID**: 42f8f1a2-4228-11ec-aade-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_curl` Processes.process IN ("*-T *","*--upload-file *", "*-d *", "*--data *", "*-F *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_curl_upload_to_remote_destination_filter`
```

#### Associated Analytic Story
* [Ingress Tool Transfer](/stories/ingress_tool_transfer)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### Kill Chain Phase
* Exfiltration


#### Known False Positives
False positives may be limited to source control applications and may be required to be filtered out.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ uploading a file to a remote destination. |




#### Reference

* [https://everything.curl.dev/usingcurl/uploads](https://everything.curl.dev/usingcurl/uploads)
* [https://techcommunity.microsoft.com/t5/containers/tar-and-curl-come-to-windows/ba-p/382409](https://techcommunity.microsoft.com/t5/containers/tar-and-curl-come-to-windows/ba-p/382409)
* [https://twitter.com/d1r4c/status/1279042657508081664?s=20](https://twitter.com/d1r4c/status/1279042657508081664?s=20)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon_curl_upload.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon_curl_upload.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_curl_upload_to_remote_destination.yml) \| *version*: **1**