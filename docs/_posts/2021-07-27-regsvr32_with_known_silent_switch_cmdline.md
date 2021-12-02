---
title: "Regsvr32 with Known Silent Switch Cmdline"
excerpt: "Signed Binary Proxy Execution, Regsvr32"
categories:
  - Endpoint
last_modified_at: 2021-07-27
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Regsvr32
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies Regsvr32.exe utilizing the silent switch to load DLLs. This technique has most recently been seen in IcedID campaigns to load its initial dll that will download the 2nd stage loader that will download and decrypt the config payload. The switch type may be either a hyphen `-` or forward slash `/`. This behavior is typically found with `-s`, and it is possible there are more switch types that may be used. \ During triage, review parallel processes and capture any artifacts that may have landed on disk. Isolate and contain the endpoint as necessary.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-27
- **Author**: Teoderick Contreras, Splunk
- **ID**: c9ef7dc4-eeaf-11eb-b2b6-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_regsvr32` by Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.original_file_name Processes.dest Processes.process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| where match(process,"(?i)[\-
|\/][Ss]{1}") 
| `regsvr32_with_known_silent_switch_cmdline_filter`
```

#### Associated Analytic Story
* [IcedID](/stories/icedid)
* [Suspicious Regsvr32 Activity](/stories/suspicious_regsvr32_activity)
* [Remcos](/stories/remcos)


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
* Exploitation


#### Known False Positives
minimal. but network operator can use this application to load dll.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to load a DLL using the silent parameter. |




#### Reference

* [https://app.any.run/tasks/56680cba-2bbc-4b34-8633-5f7878ddf858/](https://app.any.run/tasks/56680cba-2bbc-4b34-8633-5f7878ddf858/)
* [https://regexr.com/699e2](https://regexr.com/699e2)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/regsvr32_with_known_silent_switch_cmdline.yml) \| *version*: **2**