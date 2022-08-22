---
title: "Windows MSIExec With Network Connections"
excerpt: "Msiexec
"
categories:
  - Endpoint
last_modified_at: 2022-06-16
toc: true
toc_label: ""
tags:
  - Msiexec
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies MSIExec with any network connection over port 443 or 80. Typically, MSIExec does not perform network communication to the internet.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-16
- **Author**: Michael Haag, Splunk
- **ID**: 827409a1-5393-4d8d-8da4-bbb297c262a7


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | Msiexec | Defense Evasion |

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

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where `process_msiexec` by _time Processes.process_id Processes.process_name Processes.dest Processes.process_path Processes.process Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| join  process_id [
| tstats `security_content_summariesonly` count FROM datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN ("80","443") by All_Traffic.process_id All_Traffic.dest All_Traffic.dest_port All_Traffic.dest_ip 
| `drop_dm_object_name(All_Traffic)` ] 
| table _time dest parent_process_name process_name process_path process process_id dest_port dest_ip 
| `windows_msiexec_with_network_connections_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_msiexec](https://github.com/splunk/security_content/blob/develop/macros/process_msiexec.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_msiexec_with_network_connections_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_id
* Processes.process_name
* Processes.dest
* Processes.process_path
* Processes.process
* Processes.parent_process_name
* All_Traffic.process_id
* All_Traffic.dest
* All_Traffic.dest_port
* All_Traffic.dest_ip


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product. Add parent process as a filter, filter known good processes. This may be voluminous due to the join on process_id. All_Traffic does not have process_guid, yet.

#### Known False Positives
False positives will be present and filtering is required.

#### Associated Analytic story
* [Windows System Binary Proxy Execution MSIExec](/stories/windows_system_binary_proxy_execution_msiexec)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | An instance of $process_name$ was identified on endpoint $dest$ contacting a remote destination. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/](https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_msiexec_with_network_connections.yml) \| *version*: **1**