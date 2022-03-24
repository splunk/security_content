---
title: "Windows Curl Download to Suspicious Path"
excerpt: "Ingress Tool Transfer
"
categories:
  - Endpoint
last_modified_at: 2021-10-19
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of Windows Curl.exe downloading a file to a suspicious location. \
-O or --output is used when a file is to be downloaded and placed in a specified location. \
During triage, review parallel processes for further behavior. In addition, identify if the download was successful. If a file was downloaded, capture and analyze.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-10-19
- **Author**: Michael Haag, Splunk
- **ID**: c32f091e-30db-11ec-8738-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_curl` Processes.process IN ("*-O *","*--output*") Processes.process IN ("*\\appdata\\*","*\\programdata\\*","*\\public\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_curl_download_to_suspicious_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_curl](https://github.com/splunk/security_content/blob/develop/macros/process_curl.yml)

Note that `windows_curl_download_to_suspicious_path_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
It is possible Administrators or super users will use Curl for legitimate purposes. Filter as needed.

#### Associated Analytic story
* [IceID](/stories/iceid)
* [Ingress Tool Transfer](/stories/ingress_tool_transfer)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ to download a file to a suspicious directory. |




#### Reference

* [https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
* [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon_curl.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon_curl.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_curl_download_to_suspicious_path.yml) \| *version*: **1**