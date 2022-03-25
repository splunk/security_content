---
title: "Suspicious WAV file in Appdata Folder"
excerpt: "Screen Capture
"
categories:
  - Endpoint
last_modified_at: 2021-09-21
toc: true
toc_label: ""
tags:
  - Screen Capture
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious creation of .wav file in appdata folder. This behavior was seen in Remcos RAT malware where it put the audio recording in the appdata\audio folde as part of data collection. this recording can be send to its C2 server as part of its exfiltration to the compromised machine. creation of wav files in this folder path is not a ussual disk place used by user to save audio format file.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-09-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 5be109e6-1ac5-11ec-b421-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1113](https://attack.mitre.org/techniques/T1113/) | Screen Capture | Collection |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name=*.exe Processes.process_path="*\\appdata\\Roaming\\*" by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest 
| `drop_dm_object_name(Processes)` 
| join process_guid, _time [
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("*.wav") Filesystem.file_path = "*\\appdata\\Roaming\\*" by _time span=1h Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| fields file_name file_path process_name process_path process dest file_create_time _time ] 
| `suspicious_wav_file_in_appdata_folder_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `suspicious_wav_file_in_appdata_folder_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* file_create_time
* file_name
* file_path
* process_name
* process_path
* process


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, file_name, file_path and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
unknown

#### Associated Analytic story
* [Remcos](/stories/remcos)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | process $process_name$ creating image file $file_path$ in $dest$ |




#### Reference

* [https://success.trendmicro.com/solution/1123281-remcos-malware-information](https://success.trendmicro.com/solution/1123281-remcos-malware-information)
* [https://blog.malwarebytes.com/threat-intelligence/2021/07/remcos-rat-delivered-via-visual-basic/](https://blog.malwarebytes.com/threat-intelligence/2021/07/remcos-rat-delivered-via-visual-basic/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_agent/sysmon_wav.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_agent/sysmon_wav.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_wav_file_in_appdata_folder.yml) \| *version*: **1**