---
title: "MacOS - Re-opened Applications"
excerpt: ""
categories:
  - Endpoint
last_modified_at: 2020-02-07
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for processes referencing the plist files that determine which applications are re-opened when a user reboots their machine.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-07
- **Author**: Jamie Windley, Splunk
- **ID**: 40bb64f9-f619-4e3d-8732-328d40377c4b


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Installation
* Command & Control


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.DP
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*com.apple.loginwindow*" by Processes.user Processes.process_name Processes.parent_process_name Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `macos___re_opened_applications_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **macos_-_re-opened_applications_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.parent_process
* Processes.user
* Processes.process_name
* Processes.parent_process_name
* Processes.dest


#### How To Implement
In order to properly run this search, Splunk needs to ingest process data from your osquery deployed agents with the [splunk.conf](https://github.com/splunk/TA-osquery/blob/master/config/splunk.conf) pack enabled. Also the [TA-OSquery](https://github.com/splunk/TA-osquery) must be deployed across your indexers and universal forwarders in order to have the data populate the Endpoint data model.

#### Known False Positives
At this stage, there are no known false positives. During testing, no process events refering the com.apple.loginwindow.plist files were observed during normal operation of re-opening applications on reboot. Therefore, it can be asumed that any occurences of this in the process events would be worth investigating. In the event that the legitimate modification by the system of these files is in fact logged to the process log, then the process_name of that process can be added to an allow list.

#### Associated Analytic story
* [ColdRoot MacOS RAT](/stories/coldroot_macos_rat)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/macos_-_re-opened_applications.yml) \| *version*: **1**