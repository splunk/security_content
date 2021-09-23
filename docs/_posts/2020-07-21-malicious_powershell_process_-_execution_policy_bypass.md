---
title: "Malicious PowerShell Process - Execution Policy Bypass"
excerpt: "PowerShell"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
tags:
  - TTP
  - T1059.001
  - PowerShell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Command and Control
  - Actions on Objectives
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for PowerShell processes started with parameters used to bypass the local execution policy for scripts. These parameters are often observed in attacks leveraging PowerShell scripts as they override the default PowerShell execution policy.

- **ID**: 9be56c82-b1cc-4318-87eb-d138afaaca39
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Mauricio Velazco, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process_id) as process_id, values(Processes.parent_process_id) as parent_process_id values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=powershell.exe (Processes.process="* -ex*" OR Processes.process="* bypass *") by Processes.process_id, Processes.user, Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `malicious_powershell_process___execution_policy_bypass_filter`
```

#### Associated Analytic Story
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)
* [HAFNIUM Group](/stories/hafnium_group)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process_id
* Processes.parent_process_id
* Processes.process
* Processes.process_name
* Processes.user
* Processes.dest


#### Kill Chain Phase
* Command and Control
* Actions on Objectives


#### Known False Positives
There may be legitimate reasons to bypass the PowerShell execution policy. The PowerShell script being run with this parameter should be validated to ensure that it is legitimate.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | PowerShell local execution policy bypass attempt on $dest$ |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/encoded_powershell/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/encoded_powershell/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/malicious_powershell_process_-_execution_policy_bypass.yml) \| *version*: **4**