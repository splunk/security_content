---
title: "PowerShell Start-BitsTransfer"
excerpt: "BITS Jobs"
categories:
  - Endpoint
last_modified_at: 2021-03-29
toc: true
toc_label: ""
tags:
  - BITS Jobs
  - Defense Evasion
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Start-BitsTransfer is the PowerShell &#34;version&#34; of BitsAdmin.exe. Similar functionality is present. This technique variation is not as commonly used by adversaries, but has been abused in the past. Lesser known uses include the ability to set the `-TransferType` to `Upload` for exfiltration of files. In an instance where `Upload` is used, it is highly possible files will be archived. During triage, review parallel processes and process lineage. Capture any files on disk and review. For the remote domain or IP, what is the reputation?

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-29
- **Author**: Michael Haag, Splunk
- **ID**: 39e2605a-90d8-11eb-899e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1197](https://attack.mitre.org/techniques/T1197/) | BITS Jobs | Defense Evasion, Persistence |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_powershell` Processes.process=*start-bitstransfer* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.original_file_name Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `powershell_start_bitstransfer_filter`
```

#### Associated Analytic Story
* [BITS Jobs](/stories/bits_jobs)


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
* Exploitation


#### Known False Positives
Limited false positives. It is possible administrators will utilize Start-BitsTransfer for administrative tasks, otherwise filter based parent process or command-line arguments.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A suspicious process $process_name$ with commandline $process$ that are related to bittransfer functionality in host $dest$ |




#### Reference

* [https://isc.sans.edu/diary/Investigating+Microsoft+BITS+Activity/23281](https://isc.sans.edu/diary/Investigating+Microsoft+BITS+Activity/23281)
* [https://docs.microsoft.com/en-us/windows/win32/bits/using-windows-powershell-to-create-bits-transfer-jobs](https://docs.microsoft.com/en-us/windows/win32/bits/using-windows-powershell-to-create-bits-transfer-jobs)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_start-bitstransfer.yml) \| *version*: **2**