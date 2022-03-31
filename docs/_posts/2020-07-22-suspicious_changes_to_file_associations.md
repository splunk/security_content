---
title: "Suspicious Changes to File Associations"
excerpt: "Change Default File Association
"
categories:
  - Deprecated
last_modified_at: 2020-07-22
toc: true
toc_label: ""
tags:
  - Change Default File Association
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for changes to registry values that control Windows file associations, executed by a process that is not typical for legitimate, routine changes to this area.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-07-22
- **Author**: Rico Valdez, Splunk
- **ID**: 1b989a0e-0129-4446-a695-f193a5b746fc


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1546.001](https://attack.mitre.org/techniques/T1546/001/) | Change Default File Association | Persistence, Privilege Escalation |

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

* DE.CM
* PR.PT
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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as process_name values(Processes.parent_process_name) as parent_process_name FROM datamodel=Endpoint.Processes where Processes.process_name!=Explorer.exe AND Processes.process_name!=OpenWith.exe by Processes.process_id Processes.dest 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| join [
| tstats `security_content_summariesonly` values(Registry.registry_path) as registry_path count from datamodel=Endpoint.Registry where Registry.registry_path=*\\Explorer\\FileExts* by Registry.process_id Registry.dest 
| `drop_dm_object_name("Registry")` 
| table process_id dest registry_path]
| `suspicious_changes_to_file_associations_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **suspicious_changes_to_file_associations_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this search you need to be ingesting information on registry changes that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Registry` nodes.

#### Known False Positives
There may be other processes in your environment that users may legitimately use to modify file associations. If this is the case and you are finding false positives, you can modify the search to add those processes as exceptions.

#### Associated Analytic story
* [Suspicious Windows Registry Activities](/stories/suspicious_windows_registry_activities)
* [Windows File Extension and Association Abuse](/stories/windows_file_extension_and_association_abuse)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/suspicious_changes_to_file_associations.yml) \| *version*: **4**