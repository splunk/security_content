---
title: "Windows Raw Access To Disk Volume Partition"
excerpt: "Disk Structure Wipe
, Disk Wipe
"
categories:
  - Endpoint
last_modified_at: 2022-02-25
toc: true
toc_label: ""
tags:
  - Disk Structure Wipe
  - Disk Wipe
  - Impact
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to look for suspicious raw access read to device disk partition of the host machine. This technique was seen in several attacks by adversaries or threat actor to wipe, encrypt or overwrite the boot sector of each partition as part of their impact payload for example the "hermeticwiper" malware. This detection is a good indicator that there is a process try to read or write on boot sector.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-02-25
- **Author**: Teoderick Contreras, Splunk
- **ID**: a85aa37e-9647-11ec-90c5-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1561.002](https://attack.mitre.org/techniques/T1561/002/) | Disk Structure Wipe | Impact |

| [T1561](https://attack.mitre.org/techniques/T1561/) | Disk Wipe | Impact |

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
`sysmon` EventCode=9 Device = \\Device\\HarddiskVolume* NOT (Image IN("*\\Windows\\System32\\*", "*\\Windows\\SysWOW64\\*")) 
| stats count min(_time) as firstTime max(_time) as lastTime by Image Device ProcessGuid ProcessId EventDescription EventCode Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_raw_access_to_disk_volume_partition_filter`
```

#### Macros
The SPL above uses the following Macros:
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **windows_raw_access_to_disk_volume_partition_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Computer
* Image
* Device
* ProcessGuid
* ProcessId
* EventDescription
* EventCode


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the raw access read event (like sysmon eventcode 9), process name and process guid from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
This event is really notable but we found minimal number of normal application from system32 folder like svchost.exe accessing it too. In this case we used 'system32' and 'syswow64' path as a filter for this detection.

#### Associated Analytic story
* [Caddy Wiper](/stories/caddy_wiper)
* [Data Destruction](/stories/data_destruction)
* [Hermetic Wiper](/stories/hermetic_wiper)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | Process accessing disk partition $device$ in $dest$ |


#### Reference

* [https://blog.talosintelligence.com/2022/02/threat-advisory-hermeticwiper.html](https://blog.talosintelligence.com/2022/02/threat-advisory-hermeticwiper.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/hermetic_wiper/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_raw_access_to_disk_volume_partition.yml) \| *version*: **1**