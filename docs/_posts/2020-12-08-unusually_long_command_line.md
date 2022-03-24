---
title: "Unusually Long Command Line"
excerpt: ""
categories:
  - Endpoint
last_modified_at: 2020-12-08
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

Command lines that are extremely long may be indicative of malicious activity on your hosts.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-12-08
- **Author**: David Dorsey, Splunk
- **ID**: c77162d3-f93c-45cc-80c8-22f6a4264e7f

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes by Processes.user Processes.dest Processes.process_name Processes.process 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
|  eval processlen=len(process) 
| eventstats stdev(processlen) as stdev, avg(processlen) as avg by dest 
| stats max(processlen) as maxlen, values(stdev) as stdevperhost, values(avg) as avgperhost by dest, user, process_name, process 
| `unusually_long_command_line_filter` 
|eval threshold = 3 
| where maxlen > ((threshold*stdevperhost) + avgperhost)
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `unusually_long_command_line_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.user
* Processes.dest
* Processes.process_name
* Processes.process


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships, from your endpoints to populate the Endpoint data model in the Processes node. The command-line arguments are mapped to the process field in the Endpoint data model.

#### Known False Positives
Some legitimate applications start with long command lines.

#### Associated Analytic story
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)
* [Unusual Processes](/stories/unusual_processes)
* [Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns](/stories/possible_backdoor_activity_associated_with_mudcarp_espionage_campaigns)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | Unusually long command line $Processes.process_name$ on $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/unusually_long_command_line.yml) \| *version*: **5**