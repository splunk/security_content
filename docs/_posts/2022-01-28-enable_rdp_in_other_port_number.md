---
title: "Enable RDP In Other Port Number"
excerpt: "Remote Services
"
categories:
  - Endpoint
last_modified_at: 2022-01-28
toc: true
toc_label: ""
tags:
  - Remote Services
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a modification to registry to enable rdp to a machine with different port number. This technique was seen in some atttacker tries to do lateral movement and remote access to a compromised machine to gain control of it.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-01-28
- **Author**: Teoderick Contreras, Splunk
- **ID**: 99495452-b899-11eb-96dc-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path="*HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp*" Registry.registry_value_name = "PortNumber" by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.process_guid Registry.registry_key_name 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name 
| `enable_rdp_in_other_port_number_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `enable_rdp_in_other_port_number_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_path
* Registry.dest
* Registry.user
* Registry.registry_value_name


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
unknown

#### Associated Analytic story
* [Prohibited Traffic Allowed or Protocol Mismatch](/stories/prohibited_traffic_allowed_or_protocol_mismatch)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | RDP was moved to a non-standard port on $dest$ by $user$. |




#### Reference

* [https://www.mvps.net/docs/how-to-secure-remote-desktop-rdp/](https://www.mvps.net/docs/how-to-secure-remote-desktop-rdp/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/enable_rdp_in_other_port_number.yml) \| *version*: **2**