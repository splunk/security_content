---
title: "Ntdsutil Export NTDS"
excerpt: "NTDS"
categories:
  - Endpoint
last_modified_at: 2021-01-28
toc: true
tags:
  - TTP
  - T1003.003
  - NTDS
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for signs that Ntdsutil is being used to Extract Active Directory database - NTDS.dit, typically used for offline password cracking. It may be used in normal circumstances with no command line arguments or shorthand variations of more common arguments. Ntdsutil.exe is typically seen run on a Windows Server. Typical command used to dump ntds.dit \
ntdsutil &#34;ac i ntds&#34; &#34;ifm&#34; &#34;create full C:\Temp&#34; q q \
This technique uses &#34;Install from Media&#34; (IFM), which will extract a copy of the Active Directory database. A successful export of the Active Directory database will yield a file modification named ntds.dit to the destination.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-01-28
- **Author**: Michael Haag, Patrick Bareiss, Splunk
- **ID**: da63bc76-61ae-11eb-ae93-0242ac130002


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | NTDS | Credential Access |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=ntdsutil.exe Processes.process=*ntds* Processes.process=*create*) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `ntdsutil_export_ntds_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)
* [HAFNIUM Group](/stories/hafnium_group)


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints, to populate the Endpoint data model in the Processes node. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Highly possible Server Administrators will troubleshoot with ntdsutil.exe, generating false positives.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 50.0 | 100 | 50 | Active Directory NTDS export on $dest$ |



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md#atomic-test-3---dump-active-directory-database-with-ntdsutil](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md#atomic-test-3---dump-active-directory-database-with-ntdsutil)
* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753343(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753343(v=ws.11))
* [https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf)
* [https://strontic.github.io/xcyclopedia/library/vss_ps.dll-97B15BDAE9777F454C9A6BA25E938DB3.html](https://strontic.github.io/xcyclopedia/library/vss_ps.dll-97B15BDAE9777F454C9A6BA25E938DB3.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.003/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.003/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/ntdsutil_export_ntds.yml) \| *version*: **1**