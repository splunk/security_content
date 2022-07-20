---
title: "Windows MOF Event Triggered Execution via WMI"
excerpt: "Windows Management Instrumentation Event Subscription
"
categories:
  - Endpoint
last_modified_at: 2022-07-15
toc: true
toc_label: ""
tags:
  - Windows Management Instrumentation Event Subscription
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following anaytic identifies MOFComp.exe loading a MOF file. The Managed Object Format (MOF) compiler parses a file containing MOF statements and adds the classes and class instances defined in the file to the WMI repository. Typically, MOFComp.exe does not reach out to the public internet or load a MOF file from User Profile paths. A filter and consumer is typically registered in WMI. Review parallel processes and query WMI subscriptions to gather artifacts. The default path of mofcomp.exe is C:\Windows\System32\wbem.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-15
- **Author**: Michael Haag, Splunk
- **ID**: e59b5a73-32bf-4467-a585-452c36ae10c1


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | Windows Management Instrumentation Event Subscription | Persistence, Privilege Escalation |

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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("cmd.exe", "powershell.exe") Processes.process_name=mofcomp.exe) OR (Processes.process_name=mofcomp.exe Processes.process IN ("*\\AppData\\Local\\*","*\\Users\\Public\\*", "*\\WINDOWS\\Temp\\*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_mof_event_triggered_execution_via_wmi_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_mof_event_triggered_execution_via_wmi_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
False positives may be present from automation based applications (SCCM), filtering may be required. In addition, break the query out based on volume of usage. Filter process names or f

#### Associated Analytic story
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ loading a MOF file. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1546/003/](https://attack.mitre.org/techniques/T1546/003/)
* [https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/](https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/)
* [https://docs.microsoft.com/en-us/windows/win32/wmisdk/mofcomp](https://docs.microsoft.com/en-us/windows/win32/wmisdk/mofcomp)
* [https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/](https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/)
* [https://www.sakshamdixit.com/wmi-events/](https://www.sakshamdixit.com/wmi-events/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.003/atomic_red_team/mofcomp.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.003/atomic_red_team/mofcomp.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_mof_event_triggered_execution_via_wmi.yml) \| *version*: **1**