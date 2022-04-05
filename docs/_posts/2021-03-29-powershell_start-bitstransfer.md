---
title: "PowerShell Start-BitsTransfer"
excerpt: "BITS Jobs
"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Start-BitsTransfer is the PowerShell "version" of BitsAdmin.exe. Similar functionality is present. This technique variation is not as commonly used by adversaries, but has been abused in the past. Lesser known uses include the ability to set the `-TransferType` to `Upload` for exfiltration of files. In an instance where `Upload` is used, it is highly possible files will be archived. During triage, review parallel processes and process lineage. Capture any files on disk and review. For the remote domain or IP, what is the reputation?

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-03-29
- **Author**: Michael Haag, Splunk
- **ID**: 39e2605a-90d8-11eb-899e-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1197](https://attack.mitre.org/techniques/T1197/) | BITS Jobs | Defense Evasion, Persistence |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_powershell` Processes.process=*start-bitstransfer* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.original_file_name Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `powershell_start_bitstransfer_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_powershell](https://github.com/splunk/security_content/blob/develop/macros/process_powershell.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **powershell_start-bitstransfer_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Limited false positives. It is possible administrators will utilize Start-BitsTransfer for administrative tasks, otherwise filter based parent process or command-line arguments.

#### Associated Analytic story
* [BITS Jobs](/stories/bits_jobs)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A suspicious process $process_name$ with commandline $process$ that are related to bittransfer functionality in host $dest$ |


#### Reference

* [https://isc.sans.edu/diary/Investigating+Microsoft+BITS+Activity/23281](https://isc.sans.edu/diary/Investigating+Microsoft+BITS+Activity/23281)
* [https://docs.microsoft.com/en-us/windows/win32/bits/using-windows-powershell-to-create-bits-transfer-jobs](https://docs.microsoft.com/en-us/windows/win32/bits/using-windows-powershell-to-create-bits-transfer-jobs)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_start-bitstransfer.yml) \| *version*: **2**