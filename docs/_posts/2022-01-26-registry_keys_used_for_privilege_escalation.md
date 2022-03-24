---
title: "Registry Keys Used For Privilege Escalation"
excerpt: "Image File Execution Options Injection
, Event Triggered Execution
"
categories:
  - Endpoint
last_modified_at: 2022-01-26
toc: true
toc_label: ""
tags:
  - Image File Execution Options Injection
  - Event Triggered Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for modifications to registry keys that can be used to elevate privileges. The registry keys under "Image File Execution Options" are used to intercept calls to an executable and can be used to attach malicious binaries to benign system binaries.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2022-01-26
- **Author**: David Dorsey, Teoderick Contreras, Splunk
- **ID**: c9f4b923-f8af-4155-b697-1354f5bcbc5e


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | Image File Execution Options Injection | Persistence, Privilege Escalation |

| [T1546](https://attack.mitre.org/techniques/T1546/) | Event Triggered Execution | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Registry where (Registry.registry_path="*Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options*") AND (Registry.registry_value_name=GlobalFlag OR Registry.registry_value_name=Debugger) by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid Registry.registry_key_name 
| `drop_dm_object_name(Registry)` 
|rename process_guid as proc_guid 
|join proc_guid, _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.parent_process_name Processes.parent_process Processes.process_guid 
| `drop_dm_object_name(Processes)` 
|rename process_guid as proc_guid 
| fields _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name] 
| table _time dest user parent_process_name parent_process process_name process_path process proc_guid registry_path registry_value_name registry_value_data registry_key_name 
| `registry_keys_used_for_privilege_escalation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `registry_keys_used_for_privilege_escalation_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.dest
* Registry.user


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black, or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Known False Positives
There are many legitimate applications that must execute upon system startup and will use these registry keys to accomplish that task.

#### Associated Analytic story
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)
* [Suspicious Windows Registry Activities](/stories/suspicious_windows_registry_activities)
* [Cloud Federated Credential Abuse](/stories/cloud_federated_credential_abuse)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 76.0 | 80 | 95 | A registry activity in $registry_path$ related to privilege escalation in host $dest$ |




#### Reference

* [https://blog.malwarebytes.com/101/2015/12/an-introduction-to-image-file-execution-options/](https://blog.malwarebytes.com/101/2015/12/an-introduction-to-image-file-execution-options/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.012/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.012/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/registry_keys_used_for_privilege_escalation.yml) \| *version*: **5**