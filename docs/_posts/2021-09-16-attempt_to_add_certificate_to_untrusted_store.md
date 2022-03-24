---
title: "Attempt To Add Certificate To Untrusted Store"
excerpt: "Install Root Certificate
, Subvert Trust Controls
"
categories:
  - Endpoint
last_modified_at: 2021-09-16
toc: true
toc_label: ""
tags:
  - Install Root Certificate
  - Subvert Trust Controls
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Attempt To Add Certificate To Untrusted Store

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-09-16
- **Author**: Patrick Bareiss, Rico Valdez, Splunk
- **ID**: 6bc5243e-ef36-45dc-9b12-f4a6be131159


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1553.004](https://attack.mitre.org/techniques/T1553/004/) | Install Root Certificate | Defense Evasion |

| [T1553](https://attack.mitre.org/techniques/T1553/) | Subvert Trust Controls | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime values(Processes.process) as process max(_time) as lastTime from datamodel=Endpoint.Processes where `process_certutil` (Processes.process=*-addstore*) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `attempt_to_add_certificate_to_untrusted_store_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_certutil](https://github.com/splunk/security_content/blob/develop/macros/process_certutil.yml)

Note that `attempt_to_add_certificate_to_untrusted_store_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.parent_process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model.

#### Known False Positives
There may be legitimate reasons for administrators to add a certificate to the untrusted certificate store. In such cases, this will typically be done on a large number of systems.

#### Associated Analytic story
* [Disabling Security Tools](/stories/disabling_security_tools)


#### Kill Chain Phase
* Installation
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified attempting to add a certificate to the store on endpoint $dest$ by user $user$. |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.004/T1553.004.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.004/T1553.004.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1553.004/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1553.004/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/attempt_to_add_certificate_to_untrusted_store.yml) \| *version*: **7**