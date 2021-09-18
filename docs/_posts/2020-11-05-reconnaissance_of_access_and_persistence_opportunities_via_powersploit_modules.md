---
title: "Reconnaissance of Access and Persistence Opportunities via PowerSploit modules"
excerpt: "Scheduled Task/Job, Exploitation for Privilege Escalation, Valid Accounts, Create or Modify System Process, Boot or Logon Autostart Execution, Hijack Execution Flow"
categories:
  - Endpoint
last_modified_at: 2020-11-05
toc: true
tags:
  - TTP
  - T1053
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - T1068
  - Exploitation for Privilege Escalation
  - Privilege Escalation
  - T1078
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - T1543
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - T1547
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - T1574
  - Hijack Execution Flow
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Splunk Behavioral Analytics
  - Actions on Objectives
---



#### Description

This detection identifies use of PowerSploit modules that discover opportunities for malicious access and persistence. Some examples include access to admin accounts, weak access control policies, landing paths for dropping malicious software or data to exfiltrate, registry locations to land autorun parameters, task scheduling opportunities, as well as services and system files that can be compromised.

- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-05
- **Author**: Stanislav Miskovic, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation || [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation || [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access || [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation || [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation || [T1574](https://attack.mitre.org/techniques/T1574/) | Hijack Execution Flow | Persistence, Privilege Escalation, Defense Evasion |


#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Find-LocalAdminAccess/)=true OR match_regex(cmd_line, /(?i)Find-InterestingDomainAcl/)=true OR match_regex(cmd_line, /(?i)Invoke-ACLScanner/)=true OR match_regex(cmd_line, /(?i)Find-PathDLLHijack/)=true OR match_regex(cmd_line, /(?i)Find-ProcessDLLHijack/)=true OR match_regex(cmd_line, /(?i)Get-DomainObjectAcl/)=true OR match_regex(cmd_line, /(?i)Get-ObjectAcl/)=true OR match_regex(cmd_line, /(?i)Get-DomainPolicy/)=true OR match_regex(cmd_line, /(?i)Get-ModifiablePath/)=true OR match_regex(cmd_line, /(?i)Get-ModifiableRegistryAutoRun/)=true OR match_regex(cmd_line, /(?i)Get-ModifiableScheduledTaskFile/)=true OR match_regex(cmd_line, /(?i)Get-ModifiableService/)=true OR match_regex(cmd_line, /(?i)Get-ModifiableServiceFile/)=true OR match_regex(cmd_line, /(?i)Get-PathAcl/)=true OR match_regex(cmd_line, /(?i)Get-UnattendedInstallFile/)=true OR match_regex(cmd_line, /(?i)Get-UnquotedService/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id,  "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Discovery Techniques](_stories/windows_discovery_techniques)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest, including the event ID 4688 with enabled command line logging.

#### Required field
* _time
* process
* dest_device_id
* dest_user_id


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
None identified.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 60.0 | 60 | 100 |



#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1