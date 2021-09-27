---
title: "Dump LSASS via comsvcs DLL"
excerpt: "LSASS Memory"
categories:
  - Endpoint
last_modified_at: 2020-02-21
toc: true
tags:
  - TTP
  - T1003.001
  - LSASS Memory
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect the usage of comsvcs.dll for dumping the lsass process.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-21
- **Author**: Patrick Bareiss, Splunk
- **ID**: 8943b567-f14d-4ee8-a0bb-2121d4ce3184


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_rundll32` Processes.process=*comsvcs.dll* Processes.process=*MiniDump* by Processes.user Processes.process_name Processes.original_file_name Processes.process Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `dump_lsass_via_comsvcs_dll_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [Suspicious Rundll32 Activity](/stories/suspicious_rundll32_activity)
* [HAFNIUM Group](/stories/hafnium_group)


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
None identified.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified accessing credentials using comsvcs.dll on endpoint $dest$ by user $user$. |



#### Reference

* [https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/](https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/)
* [https://twitter.com/SBousseaden/status/1167417096374050817](https://twitter.com/SBousseaden/status/1167417096374050817)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/dump_lsass_via_comsvcs_dll.yml) \| *version*: **2**