---
title: "Detect HTML Help Using InfoTech Storage Handlers"
excerpt: "Compiled HTML File"
categories:
  - Endpoint
last_modified_at: 2021-09-16
toc: true
tags:
  - TTP
  - T1218.001
  - Compiled HTML File
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies hh.exe (HTML Help) execution of a Compiled HTML Help (CHM) file using InfoTech Storage Handlers. This particular technique will load Windows script code from a compiled help file, using InfoTech Storage Handlers. itss.dll will load upon execution. Three InfoTech Storage handlers are supported - ms-its, its, mk:@MSITStore. ITSS may be used to launch a specific html/htm file from within a CHM file. CHM files may contain nearly any file type embedded. Upon a successful execution, the following script engines may be used for execution - JScript, VBScript, VBScript.Encode, JScript.Encode, JScript.Compact. Analyst may identify vbscript.dll or jscript.dll loading into hh.exe upon execution. The &#34;htm&#34; and &#34;html&#34; file extensions were the only extensions observed to be supported for the execution of Shortcut commands or WSH script code. During investigation, identify script content origination. hh.exe is natively found in C:\Windows\system32 and C:\Windows\syswow64.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-16
- **Author**: Michael Haag, Splunk
- **ID**: 0b2eefa5-5508-450d-b970-3dd2fb761aec


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.001](https://attack.mitre.org/techniques/T1218/001/) | Compiled HTML File | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_hh` Processes.process IN ("*its:*", "*mk:@MSITStore:*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_html_help_using_infotech_storage_handlers_filter`
```

#### Associated Analytic Story
* [Suspicious Compiled HTML Activity](/stories/suspicious_compiled_html_activity)


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
* Actions on Objectives


#### Known False Positives
It is rare to see instances of InfoTech Storage Handlers being used, but it does happen in some legitimate instances. Filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | $process_name$ has been identified using Infotech Storage Handlers to load a specific file within a CHM on $dest$ under user $user$. |



#### Reference

* [https://attack.mitre.org/techniques/T1218/001/](https://attack.mitre.org/techniques/T1218/001/)
* [https://www.kb.cert.org/vuls/id/851869](https://www.kb.cert.org/vuls/id/851869)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Hh/](https://lolbas-project.github.io/lolbas/Binaries/Hh/)
* [https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7](https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7)
* [https://cyberforensicator.com/2019/01/20/silence-dissecting-malicious-chm-files-and-performing-forensic-analysis/](https://cyberforensicator.com/2019/01/20/silence-dissecting-malicious-chm-files-and-performing-forensic-analysis/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_html_help_using_infotech_storage_handlers.yml) \| *version*: **2**