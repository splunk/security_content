---
title: "First Time Seen Child Process of Zoom"
excerpt: "Exploitation for Privilege Escalation
"
categories:
  - Endpoint
last_modified_at: 2020-05-20
toc: true
toc_label: ""
tags:
  - Exploitation for Privilege Escalation
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for child processes spawned by zoom.exe or zoom.us that has not previously been seen.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-05-20
- **Author**: David Dorsey, Splunk
- **ID**: e91bd102-d630-4e76-ab73-7e3ba22c5961


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.PT
* DE.CM
* PR.IP



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 8



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` min(_time) as firstTime values(Processes.parent_process_name) as parent_process_name values(Processes.parent_process_id) as parent_process_id values(Processes.process_name) as process_name values(Processes.process) as process from datamodel=Endpoint.Processes where (Processes.parent_process_name=zoom.exe OR Processes.parent_process_name=zoom.us) by Processes.process_id Processes.dest 
| `drop_dm_object_name(Processes)` 
| lookup zoom_first_time_child_process dest as dest process_name as process_name OUTPUT firstTimeSeen 
| where isnull(firstTimeSeen) OR firstTimeSeen > relative_time(now(), "`previously_seen_zoom_child_processes_window`") 
| `security_content_ctime(firstTime)` 
| table firstTime dest, process_id, process_name, parent_process_id, parent_process_name 
|`first_time_seen_child_process_of_zoom_filter`
```

#### Macros
The SPL above uses the following Macros:
* [previously_seen_zoom_child_processes_window](https://github.com/splunk/security_content/blob/develop/macros/previously_seen_zoom_child_processes_window.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **first_time_seen_child_process_of_zoom_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [zoom_first_time_child_process](https://github.com/splunk/security_content/blob/develop/lookups/zoom_first_time_child_process.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/zoom_first_time_child_process.csv)

#### Required field
* _time
* Processes.parent_process_name
* Processes.parent_process_id
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.process_id
* Processes.dest


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You should run the baseline search `Previously Seen Zoom Child Processes - Initial` to build the initial table of child processes and hostnames for this search to work. You should also schedule at the same interval as this search the second baseline search `Previously Seen Zoom Child Processes - Update` to keep this table up to date and to age out old child processes. Please update the `previously_seen_zoom_child_processes_window` macro to adjust the time window.

#### Known False Positives
A new child process of zoom isn't malicious by that fact alone. Further investigation of the actions of the child process is needed to verify any malicious behavior is taken.

#### Associated Analytic story
* [Suspicious Zoom Child Processes](/stories/suspicious_zoom_child_processes)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | Child process $process_name$ with $process_id$ spawned by zoom.exe or zoom.us which has not been previously on host $dest$ |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/zoom_child_process/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/zoom_child_process/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/first_time_seen_child_process_of_zoom.yml) \| *version*: **1**