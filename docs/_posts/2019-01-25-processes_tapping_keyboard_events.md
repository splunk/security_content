---
title: "Processes Tapping Keyboard Events"
excerpt: ""
categories:
  - Endpoint
last_modified_at: 2019-01-25
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for processes in an MacOS system that is tapping keyboard events in MacOS, and essentially monitoring all keystrokes made by a user. This is a common technique used by RATs to log keystrokes from a victim, although it can also be used by legitimate processes like Siri to react on human input

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2019-01-25
- **Author**: Jose Hernandez, Splunk
- **ID**: 2a371608-331d-4034-ae2c-21dda8f1d0ec


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Command & Control


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.DP



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 4
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

| from datamodel Alerts.Alerts 
| search app=osquery:results name=pack_osx-attacks_Keyboard_Event_Taps 
| rename columns.cmdline as cmd, columns.name as process_name, columns.pid as process_id
| dedup host,process_name 
| table host,process_name, cmd, process_id 
| `processes_tapping_keyboard_events_filter`
```

#### Macros
The SPL above uses the following Macros:

Note that **processes_tapping_keyboard_events_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* app
* name
* columns.cmdline
* columns.name
* columns.pid
* host


#### How To Implement
In order to properly run this search, Splunk needs to ingest data from your osquery deployed agents with the [osx-attacks.conf](https://github.com/facebook/osquery/blob/experimental/packs/osx-attacks.conf#L599) pack enabled. Also the [TA-OSquery](https://github.com/d1vious/TA-osquery) must be deployed across your indexers and universal forwarders in order to have the osquery data populate the Alerts data model.

#### Known False Positives
There might be some false positives as keyboard event taps are used by processes like Siri and Zoom video chat, for some good examples of processes to exclude please see [this](https://github.com/facebook/osquery/pull/5345#issuecomment-454639161) comment.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/processes_tapping_keyboard_events.yml) \| *version*: **1**