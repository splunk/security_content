---
title: "System Info Gathering Using Dxdiag Application"
excerpt: "Gather Victim Host Information
"
categories:
  - Endpoint
last_modified_at: 2021-11-19
toc: true
toc_label: ""
tags:
  - Gather Victim Host Information
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious dxdiag.exe process command-line execution. Dxdiag is used to collect the system info of the target host. This technique has been used by Remcos RATS, various actors, and other malware to collect information as part of the recon or collection phase of an attack. This behavior should rarely be seen in a corporate network, but this command line can be used by a network administrator to audit host machine specifications. Thus in some rare cases, this detection will contain false positives in its results. To triage further, analyze what commands were passed after it pipes out the result to a file for further processing.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: f92d74f2-4921-11ec-b685-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | Reconnaissance |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_dxdiag` AND Processes.process = "* /t *" by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `system_info_gathering_using_dxdiag_application_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_dxdiag](https://github.com/splunk/security_content/blob/develop/macros/process_dxdiag.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **system_info_gathering_using_dxdiag_application_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Filesystem` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
This commandline can be used by a network administrator to audit host machine specifications. Thus, a filter is needed.

#### Associated Analytic story
* [Remcos](/stories/remcos)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | dxdiag.exe process with commandline $process$ on $dest$ |


#### Reference

* [https://app.any.run/tasks/df0baf9f-8baf-4c32-a452-16562ecb19be/](https://app.any.run/tasks/df0baf9f-8baf-4c32-a452-16562ecb19be/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/t1592/host_info_dxdiag/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/t1592/host_info_dxdiag/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/system_info_gathering_using_dxdiag_application.yml) \| *version*: **1**