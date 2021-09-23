---
title: "Office Product Spawn CMD Process"
excerpt: "Mshta"
categories:
  - Endpoint
last_modified_at: 2021-07-19
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

this search is to detect a suspicious office product process that spawn cmd child process. This is commonly seen in a ms office product having macro to execute shell command to download or execute malicious lolbin relative to its malicious code. This is seen in trickbot spear phishing doc where it execute shell cmd to run mshta payload.

- **ID**: b8b19420-e892-11eb-9244-acde48001122
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-19
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name = "winword.exe" OR Processes.parent_process_name= "excel.exe" OR Processes.parent_process_name = "powerpnt.exe") Processes.process_name=cmd.exe by Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.process_guid Processes.user Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `office_product_spawn_cmd_process_filter`
```

#### Associated Analytic Story
* [Trickbot](/stories/trickbot)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* parent_process
* process_name
* process
* process_id
* process_guid


#### Kill Chain Phase
* Exploitation


#### Known False Positives
IT or network admin may create an document automation that will run shell script.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | an office product parent process $parent_process_name$ spawn child process $process_name$ in host $dest$ |



#### Reference

* [https://twitter.com/cyb3rops/status/1416050325870587910?s=21](https://twitter.com/cyb3rops/status/1416050325870587910?s=21)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/spear_phish/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/spear_phish/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_product_spawn_cmd_process.yml) \| *version*: **1**