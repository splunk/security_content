---
title: "Suspicious PlistBuddy Usage"
excerpt: "Launch Agent
, Create or Modify System Process
"
categories:
  - Endpoint
last_modified_at: 2021-02-22
toc: true
toc_label: ""
tags:
  - Launch Agent
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of a native MacOS utility, PlistBuddy, creating or modifying a properly list (.plist) file. In the instance of Silver Sparrow, the following commands were executed:\
- PlistBuddy -c "Add :Label string init_verx" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :RunAtLoad bool true" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :StartInterval integer 3600" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :ProgramArguments array" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :ProgramArguments:0 string /bin/sh" ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c "Add :ProgramArguments:1 string -c" ~/Library/Launchagents/init_verx.plist \
Upon triage, capture the property list file being written to disk and review for further indicators. Contain the endpoint and triage further.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-22
- **Author**: Michael Haag, Splunk
- **ID**: c3194009-e0eb-4f84-87a9-4070f8688f00


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1543.001](https://attack.mitre.org/techniques/T1543/001/) | Launch Agent | Persistence, Privilege Escalation |

| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=PlistBuddy (Processes.process=*LaunchAgents* OR Processes.process=*RunAtLoad* OR Processes.process=*true*) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
|  `suspicious_plistbuddy_usage_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **suspicious_plistbuddy_usage_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Some legitimate applications may use PlistBuddy to create or modify property lists and possibly generate false positives. Review the property list being modified or created to confirm.

#### Associated Analytic story
* [Silver Sparrow](/stories/silver_sparrow)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference

* [https://marcosantadev.com/manage-plist-files-plistbuddy/](https://marcosantadev.com/manage-plist-files-plistbuddy/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/suspicious_plistbuddy_usage.yml) \| *version*: **1**