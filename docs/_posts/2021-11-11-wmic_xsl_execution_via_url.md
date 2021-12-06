---
title: "WMIC XSL Execution via URL"
excerpt: "XSL Script Processing"
categories:
  - Endpoint
last_modified_at: 2021-11-11
toc: true
toc_label: ""
tags:
  - XSL Script Processing
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies `wmic.exe` loading a remote XSL (eXtensible Stylesheet Language) script. This originally was identified by Casey Smith, dubbed Squiblytwo, as an application control bypass. Many adversaries will utilize this technique to invoke JScript or VBScript within an XSL file. This technique can also execute local/remote scripts and, similar to its Regsvr32 &#34;Squiblydoo&#34; counterpart, leverages a trusted, built-in Windows tool. Adversaries may abuse any alias in Windows Management Instrumentation provided they utilize the /FORMAT switch. Upon identifying a suspicious execution, review for confirmed network connnection and script download.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-11
- **Author**: Michael Haag, Splunk
- **ID**: 787e9dd0-4328-11ec-a029-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1220](https://attack.mitre.org/techniques/T1220/) | XSL Script Processing | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_wmic` Processes.process IN ("*http://*", "*https://*") Processes.process="*/format:*" by Processes.parent_process_name Processes.original_file_name Processes.parent_process Processes.process_name Processes.process_id Processes.process Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wmic_xsl_execution_via_url_filter`
```

#### Associated Analytic Story
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


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
False positives are limited as legitimate applications typically do not download files or xsl using WMIC. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ utilizing wmic to download a remote XSL script. |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.md)
* [https://web.archive.org/web/20190814201250/https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html](https://web.archive.org/web/20190814201250/https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.md#atomic-test-4---wmic-bypass-using-remote-xsl-file](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.md#atomic-test-4---wmic-bypass-using-remote-xsl-file)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1220/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1220/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wmic_xsl_execution_via_url.yml) \| *version*: **1**