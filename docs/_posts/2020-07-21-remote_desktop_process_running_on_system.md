---
title: "Remote Desktop Process Running On System"
excerpt: "Remote Desktop Protocol
, Remote Services
"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Remote Desktop Protocol
  - Remote Services
  - Lateral Movement
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the remote desktop process mstsc.exe running on systems upon which it doesn't typically run. This is accomplished by filtering out all systems that are noted in the `common_rdp_source category` in the Assets and Identity framework.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk
- **ID**: f5939373-8054-40ad-8c64-cec478a22a4a


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Lateral Movement |

| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.AE
* PR.AC
* PR.IP



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 9
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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process=*mstsc.exe AND Processes.dest_category!=common_rdp_source by Processes.dest Processes.user Processes.process 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name(Processes)` 
| `remote_desktop_process_running_on_system_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **remote_desktop_process_running_on_system_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.dest_category
* Processes.dest
* Processes.user


#### How To Implement
To successfully implement this search, you must be ingesting data that records process activity from your hosts to populate the endpoint data model in the processes node. The search requires you to identify systems that do not commonly use remote desktop. You can use the included support search "Identify Systems Using Remote Desktop" to identify these systems. After identifying them, you will need to add the "common_rdp_source" category to that system using the Enterprise Security Assets and Identities framework. This can be done by adding an entry in the assets.csv file located in `SA-IdentityManagement/lookups`.

#### Known False Positives
Remote Desktop may be used legitimately by users on the network.

#### Associated Analytic story
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/remote_desktop_process_running_on_system.yml) \| *version*: **5**