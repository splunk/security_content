---
title: "Windows NirSoft Utilities"
excerpt: "Tool
"
categories:
  - Endpoint
last_modified_at: 2022-01-24
toc: true
toc_label: ""
tags:
  - Tool
  - Resource Development
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic assists with identifying the proces execution of commonly used utilities from NirSoft. Potentially not adversary behavior, but worth identifying to know if the software is present and being used.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-01-24
- **Author**: Michael Haag, Splunk
- **ID**: 5b2f4596-7d4c-11ec-88a7-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Tool | Resource Development |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.original_file_name Processes.process_path Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `is_nirsoft_software` 
| `windows_nirsoft_utilities_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [is_nirsoft_software](https://github.com/splunk/security_content/blob/develop/macros/is_nirsoft_software.yml)

Note that `windows_nirsoft_utilities_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives may be present. Filtering may be required before setting to alert.

#### Associated Analytic story
* [WhisperGate](/stories/whispergate)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ related to NiRSoft software usage. |




#### Reference

* [https://www.cisa.gov/uscert/ncas/alerts/TA18-201A](https://www.cisa.gov/uscert/ncas/alerts/TA18-201A)
* [http://www.nirsoft.net/](http://www.nirsoft.net/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1588.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1588.002/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_nirsoft_utilities.yml) \| *version*: **1**