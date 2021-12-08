---
title: "Suspicious PlistBuddy Usage"
excerpt: "Launch Agent, Create or Modify System Process"
categories:
  - Endpoint
last_modified_at: 2021-02-22
toc: true
toc_label: ""
tags:
  - Launch Agent
  - Persistence
  - Privilege Escalation
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of a native MacOS utility, PlistBuddy, creating or modifying a properly list (.plist) file. In the instance of Silver Sparrow, the following commands were executed:\
- PlistBuddy -c &#34;Add :Label string init_verx&#34; ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c &#34;Add :RunAtLoad bool true&#34; ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c &#34;Add :StartInterval integer 3600&#34; ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c &#34;Add :ProgramArguments array&#34; ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c &#34;Add :ProgramArguments:0 string /bin/sh&#34; ~/Library/Launchagents/init_verx.plist \
- PlistBuddy -c &#34;Add :ProgramArguments:1 string -c&#34; ~/Library/Launchagents/init_verx.plist \
Upon triage, capture the property list file being written to disk and review for further indicators. Contain the endpoint and triage further.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-22
- **Author**: Michael Haag, Splunk
- **ID**: c3194009-e0eb-4f84-87a9-4070f8688f00


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1543.001](https://attack.mitre.org/techniques/T1543/001/) | Launch Agent | Persistence, Privilege Escalation |

| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=PlistBuddy (Processes.process=*LaunchAgents* OR Processes.process=*RunAtLoad* OR Processes.process=*true*) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
|  `suspicious_plistbuddy_usage_filter`
```

#### Associated Analytic Story
* [Silver Sparrow](/stories/silver_sparrow)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Some legitimate applications may use PlistBuddy to create or modify property lists and possibly generate false positives. Review the property list being modified or created to confirm.





#### Reference

* [https://redcanary.com/blog/clipping-silver-sparrows-wings/](https://redcanary.com/blog/clipping-silver-sparrows-wings/)
* [https://marcosantadev.com/manage-plist-files-plistbuddy/](https://marcosantadev.com/manage-plist-files-plistbuddy/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/suspicious_plistbuddy_usage.yml) \| *version*: **1**