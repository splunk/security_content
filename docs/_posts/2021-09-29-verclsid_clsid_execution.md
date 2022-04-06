---
title: "Verclsid CLSID Execution"
excerpt: "Verclsid
, Signed Binary Proxy Execution
"
categories:
  - Endpoint
last_modified_at: 2021-09-29
toc: true
toc_label: ""
tags:
  - Verclsid
  - Signed Binary Proxy Execution
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a possible abuse of verclsid to execute malicious file through generate CLSID. This process is a normal application of windows to verify the CLSID COM object before it is instantiated by Windows Explorer. This hunting query can be a good pivot point to analyze what is he CLSID or COM object pointing too to check if it is a valid application or not.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-29
- **Author**: Teoderick Contreras, Splunk
- **ID**: 61e9a56a-20fa-11ec-8ba3-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218.012](https://attack.mitre.org/techniques/T1218/012/) | Verclsid | Defense Evasion |

| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

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

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_verclsid` AND Processes.process="*/S*" Processes.process="*/C*" AND  Processes.process="*{*" AND Processes.process="*}*" by  Processes.process_name Processes.original_file_name Processes.dest Processes.user Processes.parent_process_name Processes.parent_process 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `verclsid_clsid_execution_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_verclsid](https://github.com/splunk/security_content/blob/develop/macros/process_verclsid.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **verclsid_clsid_execution_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
windows can used this application for its normal COM object validation.

#### Associated Analytic story
* [Unusual Processes](/stories/unusual_processes)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | process $process_name$ to execute possible clsid commandline $process$ in $dest$ |


#### Reference

* [https://gist.github.com/NickTyrer/0598b60112eaafe6d07789f7964290d5](https://gist.github.com/NickTyrer/0598b60112eaafe6d07789f7964290d5)
* [https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/](https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.012/verclsid_exec/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.012/verclsid_exec/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/verclsid_clsid_execution.yml) \| *version*: **1**