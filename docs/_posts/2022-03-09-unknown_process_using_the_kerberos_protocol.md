---
title: "Unknown Process Using The Kerberos Protocol"
excerpt: "Use Alternate Authentication Material
"
categories:
  - Endpoint
last_modified_at: 2022-03-09
toc: true
toc_label: ""
tags:
  - Use Alternate Authentication Material
  - Defense Evasion
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a process performing an outbound connection on port 88 used by default by the network authentication protocol Kerberos. Typically, on a regular Windows endpoint, only the lsass.exe process is the one tasked with connecting to the Kerberos Distribution Center to obtain Kerberos tickets. Identifying an unknown process using this protocol may be evidence of an adversary abusing the Kerberos protocol.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2022-03-09
- **Author**: Mauricio Velazco, Splunk
- **ID**: c91a0852-9fbb-11ec-af44-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |

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

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name!=lsass.exe by _time Processes.process_id Processes.process_name Processes.dest Processes.process_path Processes.process Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| join  process_id [
| tstats `security_content_summariesonly` count FROM datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port = 88 by All_Traffic.process_id All_Traffic.dest All_Traffic.dest_port 
| `drop_dm_object_name(All_Traffic)` ] 
| table _time dest parent_process_name process_name process_path process process_id dest_port 
| `unknown_process_using_the_kerberos_protocol_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **unknown_process_using_the_kerberos_protocol_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.dest_ip
* All_Traffic.dest_port
* All_Traffic.src_ip
* Processes.process_id
* Processes.process_name
* Processes.dest
* Processes.process_path
* Processes.process
* Processes.parent_process_name


#### How To Implement
To successfully implement this search, you must be ingesting your endpoint events and populating the Endpoint and Network data models.

#### Known False Positives
Custom applications may leverage the Kerberos protocol. Filter as needed.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 |  |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://stealthbits.com/blog/how-to-detect-overpass-the-hash-attacks/](https://stealthbits.com/blog/how-to-detect-overpass-the-hash-attacks/)
* [https://www.thehacker.recipes/ad/movement/kerberos/ptk](https://www.thehacker.recipes/ad/movement/kerberos/ptk)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550/rubeus/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550/rubeus/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/unknown_process_using_the_kerberos_protocol.yml) \| *version*: **1**