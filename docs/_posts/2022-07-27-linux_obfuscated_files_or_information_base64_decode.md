---
title: "Linux Obfuscated Files or Information Base64 Decode"
excerpt: "Obfuscated Files or Information
"
categories:
  - Endpoint
last_modified_at: 2022-07-27
toc: true
toc_label: ""
tags:
  - Obfuscated Files or Information
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of base64 decode on Linux being utilized to deobfuscate a file. Identify the source of the file and determine if legitimate. Review parallel processes for further behavior before and after.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-27
- **Author**: Michael Haag, Splunk
- **ID**: 303b38b2-c03f-44e2-8f41-4594606fcfc7


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Defense Evasion |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Delivery
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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*base64 -d*","*base64 --decode*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_obfuscated_files_or_information_base64_decode_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **linux_obfuscated_files_or_information_base64_decode_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
False positives may be present and will require some tuning based on processes. Filter as needed.

#### Associated Analytic story
* [Linux Living Off The Land](/stories/linux_living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ decoding base64. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md#atomic-test-1---decode-base64-data-into-script](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md#atomic-test-1---decode-base64-data-into-script)
* [https://redcanary.com/blog/lateral-movement-with-secure-shell/](https://redcanary.com/blog/lateral-movement-with-secure-shell/)
* [https://linux.die.net/man/1/base64](https://linux.die.net/man/1/base64)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/linux-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/linux-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_obfuscated_files_or_information_base64_decode.yml) \| *version*: **1**