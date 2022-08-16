---
title: "Windows Registry Delete Task SD"
excerpt: "Scheduled Task
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2022-04-13
toc: true
toc_label: ""
tags:
  - Scheduled Task
  - Impair Defenses
  - Execution
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a process attempting to delete a scheduled task SD (Security Descriptor) from within the registry path of that task. This may occur from a non-standard process running and may not come from reg.exe. This particular behavior will remove the actual Task Name from the Task Scheduler GUI and from the command-line query - schtasks.exe /query. In addition, in order to perform this action, the user context will need to be SYSTEM.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-04-13
- **Author**: Michael Haag, Splunk
- **ID**: ffeb7893-ff06-446f-815b-33ca73224e92


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Installation


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

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Registry where Registry.registry_path IN ("*\\Schedule\\TaskCache\\Tree\\*") Registry.user="SYSTEM" Registry.registry_value_name="SD" (Registry.action=Deleted OR Registry.action=modified) by _time  Registry.dest Registry.process_guid Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_key_name Registry.registry_value_data Registry.status Registry.action 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_registry_delete_task_sd_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_registry_delete_task_sd_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest
* Processes.process_id
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.process_guid


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited as the activity is not common to delete ONLY the SD from the registry. Filter as needed. Update the analytic Modified or Deleted values based on product that is in the datamodel.

#### Associated Analytic story
* [Windows Registry Abuse](/stories/windows_registry_abuse)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | A scheduled task security descriptor was deleted from the registry on $dest$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/](https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)
* [https://gist.github.com/MHaggis/5f7fd6745915166fc6da863d685e2728](https://gist.github.com/MHaggis/5f7fd6745915166fc6da863d685e2728)
* [https://gist.github.com/MHaggis/b246e2fae6213e762a6e694cabaf0c17](https://gist.github.com/MHaggis/b246e2fae6213e762a6e694cabaf0c17)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/taskschedule/sd_delete_windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/taskschedule/sd_delete_windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_registry_delete_task_sd.yml) \| *version*: **1**