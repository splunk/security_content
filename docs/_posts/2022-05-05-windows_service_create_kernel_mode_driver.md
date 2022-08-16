---
title: "Windows Service Create Kernel Mode Driver"
excerpt: "Windows Service
, Create or Modify System Process
, Exploitation for Privilege Escalation
"
categories:
  - Endpoint
last_modified_at: 2022-05-05
toc: true
toc_label: ""
tags:
  - Windows Service
  - Create or Modify System Process
  - Exploitation for Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifes a new kernel driver being added to Windows using sc.exe. Adding a Kernel driver is not common day to day and should be investigated to further understand the source.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-05-05
- **Author**: Michael Haag, Splunk
- **ID**: 0b4e3b06-1b2b-4885-b752-cf06d12a90cb


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |

| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=sc.exe Processes.process="*kernel*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_service_create_kernel_mode_driver_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_service_create_kernel_mode_driver_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
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
False positives may be present based on common applications adding new drivers, however, filter as needed.

#### Associated Analytic story
* [Windows Drivers](/stories/windows_drivers)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 60 | 80 | Service control, $process_name$, loaded a new kernel mode driver on $dest$ by $user$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.aon.com/cyber-solutions/aon_cyber_labs/yours-truly-signed-av-driver-weaponizing-an-antivirus-driver/](https://www.aon.com/cyber-solutions/aon_cyber_labs/yours-truly-signed-av-driver-weaponizing-an-antivirus-driver/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/sc_kernel.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/sc_kernel.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_service_create_kernel_mode_driver.yml) \| *version*: **1**