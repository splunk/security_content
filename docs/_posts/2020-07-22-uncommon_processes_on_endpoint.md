---
title: "Uncommon Processes On Endpoint"
excerpt: "Malicious File
"
categories:
  - Deprecated
last_modified_at: 2020-07-22
toc: true
toc_label: ""
tags:
  - Malicious File
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for applications on the endpoint that you have marked as uncommon.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-22
- **Author**: David Dorsey, Splunk
- **ID**: 29ccce64-a10c-4389-a45f-337cb29ba1f7


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | Execution |

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

* ID.AM
* PR.DS



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 2



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes by Processes.dest Processes.user Processes.process Processes.process_name 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name(Processes)` 
| `uncommon_processes` 
|`uncommon_processes_on_endpoint_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [uncommon_processes](https://github.com/splunk/security_content/blob/develop/macros/uncommon_processes.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **uncommon_processes_on_endpoint_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model. This search uses a lookup file `uncommon_processes_default.csv` to track various features of process names that are usually uncommon in most environments. Please consider updating `uncommon_processes_local.csv` to hunt for processes that are uncommon in your environment.

#### Known False Positives
None identified

#### Associated Analytic story
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)
* [Unusual Processes](/stories/unusual_processes)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/uncommon_processes_on_endpoint.yml) \| *version*: **4**