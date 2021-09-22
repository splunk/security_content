---
title: "Dump LSASS via procdump Rename"
excerpt: "LSASS Memory"
categories:
  - Endpoint
last_modified_at: 2021-02-01
toc: true
tags:
  - TTP
  - T1003.001
  - LSASS Memory
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



[Try in Splunk Cloud](#https://www.splunk.com/en_us/software/splunk-cloud-platform.html){: .btn .btn--success}

#### Description

Detect a renamed instance of procdump.exe dumping the lsass process. This query looks for both -mm and -ma usage. -mm will produce a mini dump file and -ma will write a dump file with all process memory. Both are highly suspect and should be reviewed. Modify the query as needed.\
During triage, confirm this is procdump.exe executing. If it is the first time a Sysinternals utility has been ran, it is possible there will be a -accepteula on the command line. Review other endpoint data sources for cross process (injection) into lsass.exe.

- **ID**: 21276daa-663d-11eb-ae93-0242ac130002
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-02-01
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |


#### Search

```
`sysmon` OriginalFileName=procdump  process_name!=procdump*.exe  EventID=1 (CommandLine=*-ma* OR CommandLine=*-mm*) CommandLine=*lsass* 
| rename Computer as dest 
|  stats count min(_time) as firstTime max(_time) as lastTime by dest, parent_process_name, process_name, OriginalFileName, CommandLine 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `dump_lsass_via_procdump_rename_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [HAFNIUM Group](/stories/hafnium_group)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* OriginalFileName
* process_name
* EventID
* CommandLine
* Computer
* parent_process_name


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 80.0 | 80 | 100 |



#### Reference

* [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)
* [https://docs.microsoft.com/en-us/sysinternals/downloads/procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-procdump](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-procdump)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/dump_lsass_via_procdump_rename.yml) \| *version*: **1**