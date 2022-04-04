---
title: "Excessive Usage Of Cacls App"
excerpt: "File and Directory Permissions Modification
"
categories:
  - Endpoint
last_modified_at: 2021-05-07
toc: true
toc_label: ""
tags:
  - File and Directory Permissions Modification
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies excessive usage of `cacls.exe`, `xcacls.exe` or `icacls.exe` application to change file or folder permission. This behavior is commonly seen where the adversary attempts to impair some users from deleting or accessing its malware components or artifact from the compromised system.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-05-07
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0bdf6092-af17-11eb-939a-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1222](https://attack.mitre.org/techniques/T1222/) | File and Directory Permissions Modification | Defense Evasion |

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

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.process_id) as process_id  values(Processes.process_name) as process_name count min(_time) as firstTime max(_time) as lastTime  from datamodel=Endpoint.Processes where Processes.process_name = "cacls.exe" OR Processes.process_name = "icacls.exe" OR Processes.process_name = "XCACLS.exe" by Processes.parent_process_name Processes.parent_process Processes.dest Processes.user _time span=1m 
| where count >=10 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_usage_of_cacls_app_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **excessive_usage_of_cacls_app_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.process_id
* Processes.process_name
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Administrators or administrative scripts may use this application. Filter as needed.

#### Associated Analytic story
* [XMRig](/stories/xmrig)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An excessive amount of $process_name$ was executed on $dest$ attempting to modify permissions. |


#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/excessive_usage_of_cacls_app.yml) \| *version*: **1**