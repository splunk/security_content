---
title: "Get DomainUser with PowerShell"
excerpt: "Domain Account"
categories:
  - Endpoint
last_modified_at: 2021-08-24
toc: true
tags:
  - TTP
  - T1087.002
  - Domain Account
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Reconnaissance
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for the execution of `powershell.exe` with command-line arguments utilized to enumerate domain users. `Get-DomainUser` is part of PowerView, a PowerShell tool used to perform enumeration on Windows domains. Red Teams and adversaries alike may leverage PowerView to enumerate domain users for situational awareness and Active Directory Discovery.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-24
- **Author**: Teoderick Contreras, Mauricio Velazco, Splunk
- **ID**: 9a5a41d6-04e7-11ec-923c-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | Discovery |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="cmd.exe" OR Processes.process_name="powershell*") AND Processes.process = "*Get-DomainUser*" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `get_domainuser_with_powershell_filter`
```

#### Associated Analytic Story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id
* Processes.parent_process_name


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
Administrators or power users may use this command for troubleshooting.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | an instance of process $process_name$ with commandline $process$ in $dest$ |



#### Reference

* [https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainUser/](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainUser/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/get_domainuser_with_powershell.yml) \| *version*: **1**