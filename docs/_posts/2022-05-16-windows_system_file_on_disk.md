---
title: "Windows System File on Disk"
excerpt: "Exploitation for Privilege Escalation
"
categories:
  - Endpoint
last_modified_at: 2022-05-16
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic will assist with identifying new .sys files introduced in the environment. This query is meant to identify sys file creates on disk. There will be noise, but reducing common process names or applications should help to limit any volume. The idea is to identify new sys files written to disk and identify them before they're added as a new kernel mode driver.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-05-16
- **Author**: Michael Haag, Splunk
- **ID**: 993ce99d-9cdd-42c7-a2cf-733d5954e5a6


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

* Delivery


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name="*.sys*" by _time span=1h Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.file_path Filesystem.file_hash 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `windows_system_file_on_disk_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_system_file_on_disk_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on files from your endpoints into the `Endpoint` datamodel in the `Filesystem` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product. In addition, filtering may occur by adding NOT (Filesystem.file_path IN ("*\\Windows\\*", "*\\Program File*", "*\\systemroot\\*","%SystemRoot%*", "system32\*")). This will level out the noise generated to potentally lead to generating notables.

#### Known False Positives
False positives will be present. Filter as needed.

#### Associated Analytic story
* [Windows Drivers](/stories/windows_drivers)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 10.0 | 20 | 50 | A new driver is present on $dest$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/](https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/sysmon_sys_filemod.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/sysmon_sys_filemod.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_system_file_on_disk.yml) \| *version*: **2**