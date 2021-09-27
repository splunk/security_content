---
title: "Spoolsv Writing a DLL - Sysmon"
excerpt: "Print Processors"
categories:
  - Endpoint
last_modified_at: 2021-07-01
toc: true
tags:
  - TTP
  - T1547.012
  - Print Processors
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a `.dll` being written by `spoolsv.exe`. This was identified during our testing of CVE-2021-34527 previously(CVE-2021-1675) or PrintNightmare. Typically, this is not normal behavior for `spoolsv.exe` to write a `.dll`. Current POC code used will write the suspicious DLL to disk within a path of `\spool\drivers\x64\`. During triage, isolate the endpoint and review for source of exploitation. Capture any additional file modification events.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-01
- **Author**: Mauricio Velazco, Michael Haag, Splunk
- **ID**: 347fd388-da87-11eb-836d-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1547.012](https://attack.mitre.org/techniques/T1547/012/) | Print Processors | Persistence, Privilege Escalation |


#### Search

```
`sysmon` EventID=11 process_name=spoolsv.exe file_path="*\\spool\\drivers\\x64\\*" file_name=*.dll 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, UserID, process_name, file_path, file_name, TargetFilename, process_id 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `spoolsv_writing_a_dll___sysmon_filter`
```

#### Associated Analytic Story
* [PrintNightmare CVE-2021-34527](/stories/printnightmare_cve-2021-34527)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed rundll32.exe may be used.

#### Required field
* _time
* dest
* UserID
* process_name
* file_path
* file_name
* TargetFilename


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Limited false positives. Filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | $process_name$ has been identified writing dll&#39;s to $file_path$ on endpoint $dest$. This behavior is suspicious and related to PrintNightmare. |



#### Reference

* [https://github.com/cube0x0/impacket/commit/73b9466c17761384ece11e1028ec6689abad6818](https://github.com/cube0x0/impacket/commit/73b9466c17761384ece11e1028ec6689abad6818)
* [https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/](https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/)
* [https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/](https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/)
* [https://www.reddit.com/r/msp/comments/ob6y02/critical_vulnerability_printnightmare_exposes](https://www.reddit.com/r/msp/comments/ob6y02/critical_vulnerability_printnightmare_exposes)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/spoolsv_writing_a_dll_-_sysmon.yml) \| *version*: **1**