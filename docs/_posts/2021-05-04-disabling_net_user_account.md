---
title: "Disabling Net User Account"
excerpt: "Account Access Removal"
categories:
  - Endpoint
last_modified_at: 2021-05-04
toc: true
tags:
  - TTP
  - T1531
  - Account Access Removal
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify a suspicious command-line that disables a user account using the `net.exe` utility native to Windows. This technique may used by the adversaries to interrupt availability of such users to do their malicious act.

- **ID**: c0325326-acd6-11eb-98c2-acde48001122
- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-04
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1531](https://attack.mitre.org/techniques/T1531/) | Account Access Removal | Impact |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="net.exe" OR Processes.process_name="net1.exe" AND Processes.process="*user*" AND Processes.process="*/active:no*" by  Processes.process_name Processes.dest Processes.user Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `disabling_net_user_account_filter`
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed net.exe/net1.exe may be used.

#### Required field
* _time
* Processes.process_name
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_id
* Processes.parent_process


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | An instance of $parent_process_name$ spawning $process_name$ was identified disabling a user account on endpoint $dest$ by user $user$. |



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disabling_net_user_account.yml) \| *version*: **1**