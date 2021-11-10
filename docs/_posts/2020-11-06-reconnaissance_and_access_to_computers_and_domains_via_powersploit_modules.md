---
title: "Reconnaissance and Access to Computers and Domains via PowerSploit modules"
excerpt: "Gather Victim Host Information, Gather Victim Network Information, Account Discovery"
categories:
  - Endpoint
last_modified_at: 2020-11-06
toc: true
toc_label: ""
tags:
  - Gather Victim Host Information
  - Reconnaissance
  - Gather Victim Network Information
  - Reconnaissance
  - Account Discovery
  - Discovery
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies access to PowerSploit modules that discover computers, servers and domains that can be accessed or taken over.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-06
- **Author**: Stanislav Miskovic, Splunk
- **ID**: fe1c4c5a-09f3-4b43-8129-560a7f38a08b


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | Reconnaissance |

| [T1590](https://attack.mitre.org/techniques/T1590/) | Gather Victim Network Information | Reconnaissance |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Get-ComputerDetail/)=true OR match_regex(cmd_line, /(?i)Get-Domain/)=true OR match_regex(cmd_line, /(?i)Get-NetDomain/)=true OR match_regex(cmd_line, /(?i)Get-DomainComputer/)=true OR match_regex(cmd_line, /(?i)Get-NetComputer/)=true OR match_regex(cmd_line, /(?i)Get-DomainController/)=true OR match_regex(cmd_line, /(?i)Get-NetDomainController/)=true OR match_regex(cmd_line, /(?i)Get-DomainFileServer/)=true OR match_regex(cmd_line, /(?i)Get-NetFileServer/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id,  "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Windows Discovery Techniques](/stories/windows_discovery_techniques)


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

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | PowerSploit malware is seaching for or accessing domain controllers, computers, file servers, etc. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/reconnaissance_and_access_to_computers_and_domains_via_powersploit_modules.yml) \| *version*: **1**