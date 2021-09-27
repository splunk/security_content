---
title: "Winword Spawning Windows Script Host"
excerpt: "Spearphishing Attachment"
categories:
  - Endpoint
last_modified_at: 2021-04-12
toc: true
tags:
  - TTP
  - T1566.001
  - Spearphishing Attachment
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following detection identifies Microsoft Winword.exe spawning Windows Script Host - `cscript.exe` or `wscript.exe`. Typically, this is not common behavior and not default with Winword.exe. Winword.exe will generally be found in the following path `C:\Program Files\Microsoft Office\root\Office16` (version will vary). `cscript.exe` or `wscript.exe` default location is `c:\windows\system32\` or c:windows\syswow64\`. `cscript.exe` or `wscript.exe` spawning from Winword.exe is common for a spearphishing attachment and is actively used. Albeit, the command-line executed will most likely be obfuscated and captured via another detection. During triage, review parallel processes and identify any files that may have been written. Review the reputation of the remote destination and block accordingly.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-12
- **Author**: Michael Haag, Splunk
- **ID**: 637e1b5c-9be1-11eb-9c32-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="winword.exe" Processes.process_name IN ("cscript.exe", "wscript.exe") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `winword_spawning_windows_script_host_filter`
```

#### Associated Analytic Story
* [Spearphishing Attachment](/stories/spearphishing_attachment)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* process_name
* process_id
* parent_process_name
* dest
* user
* parent_process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
There will be limited false positives and it will be different for every environment. Tune by child process or command-line as needed.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | User $user$ on $dest$ spawned Windows Script Host from Winword.exe |



#### Reference

* [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_wsh.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_wsh.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/winword_spawning_windows_script_host.yml) \| *version*: **1**