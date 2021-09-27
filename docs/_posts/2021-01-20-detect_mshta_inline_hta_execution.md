---
title: "Detect mshta inline hta execution"
excerpt: "Mshta"
categories:
  - Endpoint
last_modified_at: 2021-01-20
toc: true
tags:
  - TTP
  - T1218.005
  - Mshta
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies &#34;mshta.exe&#34; execution with inline protocol handlers. &#34;JavaScript&#34;, &#34;VBScript&#34;, and &#34;About&#34; are the only supported options when invoking HTA content directly on the command-line. The search will return the first time and last time these command-line arguments were used for these executions, as well as the target system, the user, process &#34;mshta.exe&#34; and its parent process.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-20
- **Author**: Bhavin Patel, Michael Haag, Splunk
- **ID**: a0873b32-5b68-11eb-ae93-0242ac130002


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=mshta.exe (Processes.process=*vbscript* OR Processes.process=*javascript* OR Processes.process=*about*) by Processes.user Processes.process_name Processes.parent_process_name Processes.dest  
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_mshta_inline_hta_execution_filter`
```

#### Associated Analytic Story
* [Suspicious MSHTA Activity](/stories/suspicious_mshta_activity)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

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
Although unlikely, some legitimate applications may exhibit this behavior, triggering a false positive.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ executing with inline HTA, indicative of defense evasion. |



#### Reference

* [https://github.com/redcanaryco/AtomicTestHarnesses](https://github.com/redcanaryco/AtomicTestHarnesses)
* [https://redcanary.com/blog/introducing-atomictestharnesses/](https://redcanary.com/blog/introducing-atomictestharnesses/)
* [https://docs.microsoft.com/en-us/windows/win32/search/-search-3x-wds-extidx-prot-implementing](https://docs.microsoft.com/en-us/windows/win32/search/-search-3x-wds-extidx-prot-implementing)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_mshta_inline_hta_execution.yml) \| *version*: **5**