---
title: "Child Processes of Spoolsv exe"
excerpt: "Exploitation for Privilege Escalation"
categories:
  - Endpoint
last_modified_at: 2020-03-16
toc: true
tags:
  - TTP
  - T1068
  - Exploitation for Privilege Escalation
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for child processes of spoolsv.exe. This activity is associated with a POC privilege-escalation exploit associated with CVE-2018-8440. Spoolsv.exe is the process associated with the Print Spooler service in Windows and typically runs as SYSTEM.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-03-16
- **Author**: Rico Valdez, Splunk
- **ID**: aa0c4aeb-5b18-41c4-8c07-f1442d7599df


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation |



#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process_name) as process_name values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=spoolsv.exe AND Processes.process_name!=regsvr32.exe by Processes.dest Processes.parent_process Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `child_processes_of_spoolsv_exe_filter` 
```

#### Associated Analytic Story
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints to populate the Endpoint data model in the Processes node. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model. Update the `children_of_spoolsv_filter` macro to filter out legitimate child processes spawned by spoolsv.exe.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.process_name
* Processes.dest
* Processes.parent_process
* Processes.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Some legitimate printer-related processes may show up as children of spoolsv.exe. You should confirm that any activity as legitimate and may be added as exclusions in the search.




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/child_processes_of_spoolsv_exe.yml) \| *version*: **3**