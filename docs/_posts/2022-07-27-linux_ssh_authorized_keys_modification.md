---
title: "Linux SSH Authorized Keys Modification"
excerpt: "SSH Authorized Keys
"
categories:
  - Endpoint
last_modified_at: 2022-07-27
toc: true
toc_label: ""
tags:
  - SSH Authorized Keys
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies based on process execution the modification of SSH Authorized Keys. Adversaries perform this behavior to persist on endpoints. During triage, review parallel processes and capture any additional file modifications for review.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-27
- **Author**: Michael Haag, Splunk
- **ID**: f5ab595e-28e5-4327-8077-5008ba97c850


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | SSH Authorized Keys | Persistence |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where  Processes.process_name IN ("bash","cat") Processes.process IN ("*/authorized_keys*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_ssh_authorized_keys_modification_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **linux_ssh_authorized_keys_modification_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Filtering will be required as system administrators will add and remove. One way to filter query is to add "echo".

#### Associated Analytic story
* [Linux Living Off The Land](/stories/linux_living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ modifying SSH Authorized Keys. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://redcanary.com/blog/lateral-movement-with-secure-shell/](https://redcanary.com/blog/lateral-movement-with-secure-shell/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.004/T1098.004.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.004/T1098.004.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/ssh_authorized_keys/authkey_linux-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/ssh_authorized_keys/authkey_linux-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_ssh_authorized_keys_modification.yml) \| *version*: **1**