---
title: "Dump LSASS via procdump"
excerpt: "LSASS Memory"
categories:
  - Endpoint
last_modified_at: 2021-09-16
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

Detect procdump.exe dumping the lsass process. This query looks for both -mm and -ma usage. -mm will produce a mini dump file and -ma will write a dump file with all process memory. Both are highly suspect and should be reviewed. This query does not monitor for the internal name (original_file_name=procdump) of the PE or look for procdump64.exe. Modify the query as needed.\
During triage, confirm this is procdump.exe executing. If it is the first time a Sysinternals utility has been ran, it is possible there will be a -accepteula on the command line. Review other endpoint data sources for cross process (injection) into lsass.exe.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-16
- **Author**: Michael Haag, Splunk
- **ID**: 3742ebfe-64c2-11eb-ae93-0242ac130002


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_procdump` (Processes.process=*-ma* OR Processes.process=*-mm*) Processes.process=*lsass* by Processes.user Processes.process_name Processes.process Processes.original_file_name Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `dump_lsass_via_procdump_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [HAFNIUM Group](/stories/hafnium_group)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified attempting to dump lsass.exe on endpoint $dest$ by user $user$. |



#### Reference

* [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)
* [https://docs.microsoft.com/en-us/sysinternals/downloads/procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-procdump](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-procdump)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/dump_lsass_via_procdump.yml) \| *version*: **2**