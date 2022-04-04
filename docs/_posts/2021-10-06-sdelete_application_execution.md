---
title: "Sdelete Application Execution"
excerpt: "Data Destruction
, File Deletion
, Indicator Removal on Host
"
categories:
  - Endpoint
last_modified_at: 2021-10-06
toc: true
toc_label: ""
tags:
  - Data Destruction
  - File Deletion
  - Indicator Removal on Host
  - Impact
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect the execution of sdelete.exe application sysinternal tools. This tool is one of the most use tool of malware and adversaries to remove or clear their tracks and artifact in the targetted host. This tool is designed to delete securely a file in file system that remove the forensic evidence on the machine. A good TTP query to check why user execute this application which is not a common practice.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-10-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: 31702fc0-2682-11ec-85c3-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |

| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | Defense Evasion |

| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_sdelete` by  Processes.process_name Processes.original_file_name Processes.dest Processes.user Processes.parent_process_name Processes.parent_process 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `sdelete_application_execution_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_sdelete](https://github.com/splunk/security_content/blob/develop/macros/process_sdelete.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **sdelete_application_execution_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
user may execute and use this application

#### Associated Analytic story
* [Masquerading - Rename System Utilities](/stories/masquerading_-_rename_system_utilities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | sdelete process $process_name$ executed in $dest$ |


#### Reference

* [https://app.any.run/tasks/956f50be-2c13-465a-ac00-6224c14c5f89/](https://app.any.run/tasks/956f50be-2c13-465a-ac00-6224c14c5f89/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/sdelete/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/sdelete/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/sdelete_application_execution.yml) \| *version*: **1**