---
title: "Excessive Usage Of Net App"
excerpt: "Account Access Removal"
categories:
  - Endpoint
last_modified_at: 2021-05-06
toc: true
tags:
  - Anomaly
  - T1531
  - Account Access Removal
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies excessive usage of `net.exe` or `net1.exe` within a bucket of time (1 minute). This behavior was seen in a Monero incident where the adversary attempts to create many users, delete and disable users as part of its malicious behavior.

- **ID**: 45e52536-ae42-11eb-b5c6-acde48001122
- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-06
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1531](https://attack.mitre.org/techniques/T1531/) | Account Access Removal | Impact |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.process_id) as process_id count min(_time) as firstTime max(_time) as lastTime  from datamodel=Endpoint.Processes where Processes.process_name = "net.exe" OR Processes.process_name = "net1.exe" by Processes.process_name Processes.parent_process_name Processes.dest Processes.user _time span=1m 
| where count >=10 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_usage_of_net_app_filter`
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed net.exe may be used.

#### Required field
* _time
* Processes.process
* Processes.process_id
* Processes.process_name
* Processes.parent_process_name
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown. Filter as needed. Modify the time span as needed.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 28.0 | 40 | 70 | Excessive usage of net1.exe or net.exe within 1m, with command line $process$ has been detected on $dest$ by $user$ |



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/excessive_usage_of_net_app.yml) \| *version*: **1**