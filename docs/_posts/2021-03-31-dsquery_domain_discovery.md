---
title: "DSQuery Domain Discovery"
excerpt: "Domain Trust Discovery"
categories:
  - Endpoint
last_modified_at: 2021-03-31
toc: true
toc_label: ""
tags:
  - Domain Trust Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies &#34;dsquery.exe&#34; execution with arguments looking for `TrustedDomain` query directly on the command-line. This is typically indicative of an Administrator or adversary perform domain trust discovery. Note that this query does not identify any other variations of &#34;Dsquery.exe&#34; usage.\
Within this detection, it is assumed `dsquery.exe` is not moved or renamed.\
The search will return the first time and last time these command-line arguments were used for these executions, as well as the target system, the user, process &#34;dsquery.exe&#34; and its parent process.\
DSQuery.exe is natively found in `C:\Windows\system32` and `C:\Windows\syswow64` and only on Server operating system.\
The following DLL(s) are loaded when DSQuery.exe is launched `dsquery.dll`. If found loaded by another process, it is possible dsquery is running within that process context in memory.\
In addition to trust discovery, review parallel processes for additional behaviors performed. Identify the parent process and capture any files (batch files, for example) being used.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-31
- **Author**: Michael Haag, Splunk
- **ID**: cc316032-924a-11eb-91a2-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1482](https://attack.mitre.org/techniques/T1482/) | Domain Trust Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=dsquery.exe Processes.process=*trustedDomain* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `dsquery_domain_discovery_filter`
```

#### Associated Analytic Story
* [Domain Trust Discovery](/stories/domain_trust_discovery)
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

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
* Exploitation


#### Known False Positives
Limited false positives. If there is a true false positive, filter based on command-line or parent process.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | An instance of $parent_process_name$ spawning $process_name$ was identified performing domain discovery on endpoint $dest$ by user $user$. |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md)
* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732952(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732952(v=ws.11))
* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc754232(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc754232(v=ws.11))



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/dsquery_domain_discovery.yml) \| *version*: **1**