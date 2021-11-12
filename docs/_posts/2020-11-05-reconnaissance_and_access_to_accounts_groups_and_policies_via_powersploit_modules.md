---
title: "Reconnaissance and Access to Accounts Groups and Policies via PowerSploit modules"
excerpt: "Valid Accounts, Account Discovery, Domain Policy Modification"
categories:
  - Endpoint
last_modified_at: 2020-11-05
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Account Discovery
  - Discovery
  - Domain Policy Modification
  - Defense Evasion
  - Privilege Escalation
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies access to PowerSploit modules that discover accounts, groups and policies that can be accessed or taken over.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-05
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 63422f8e-766c-468f-8133-2ba6795e263b


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

| [T1484](https://attack.mitre.org/techniques/T1484/) | Domain Policy Modification | Defense Evasion, Privilege Escalation |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Find-DomainLocalGroupMember/)=true OR match_regex(cmd_line, /(?i)Invoke-EnumerateLocalAdmin/)=true OR match_regex(cmd_line, /(?i)Find-DomainUserEvent/)=true OR match_regex(cmd_line, /(?i)Invoke-EventHunter/)=true OR match_regex(cmd_line, /(?i)Find-DomainUserLocation/)=true OR match_regex(cmd_line, /(?i)Invoke-UserHunter/)=true OR match_regex(cmd_line, /(?i)Get-DomainForeignGroupMember/)=true OR match_regex(cmd_line, /(?i)Find-ForeignGroup/)=true OR match_regex(cmd_line, /(?i)Get-DomainForeignUser/)=true OR match_regex(cmd_line, /(?i)Find-ForeignUser/)=true OR match_regex(cmd_line, /(?i)Get-DomainGPO/)=true OR match_regex(cmd_line, /(?i)Get-NetGPO/)=true OR match_regex(cmd_line, /(?i)Get-DomainGPOComputerLocalGroupMapping/)=true OR match_regex(cmd_line, /(?i)Find-GPOComputerAdmin/)=true OR match_regex(cmd_line, /(?i)Get-DomainGPOLocalGroup/)=true OR match_regex(cmd_line, /(?i)Get-NetGPOGroup/)=true OR match_regex(cmd_line, /(?i)Get-DomainGPOUserLocalGroupMapping/)=true OR match_regex(cmd_line, /(?i)Find-GPOLocation/)=true OR match_regex(cmd_line, /(?i)Get-DomainGroup/)=true OR match_regex(cmd_line, /(?i)Get-NetGroup/)=true OR match_regex(cmd_line, /(?i)Get-DomainGroupMember/)=true OR match_regex(cmd_line, /(?i)Get-NetGroupMember/)=true OR match_regex(cmd_line, /(?i)Get-DomainManagedSecurityGroup/)=true OR match_regex(cmd_line, /(?i)Find-ManagedSecurityGroups/)=true OR match_regex(cmd_line, /(?i)Get-DomainOU/)=true OR match_regex(cmd_line, /(?i)Get-NetOU/)=true OR match_regex(cmd_line, /(?i)Get-DomainUser/)=true OR match_regex(cmd_line, /(?i)Get-NetUser/)=true OR match_regex(cmd_line, /(?i)Get-DomainUserEvent/)=true OR match_regex(cmd_line, /(?i)Get-UserEvent/)=true OR match_regex(cmd_line, /(?i)Get-NetLocalGroup/)=true OR match_regex(cmd_line, /(?i)Get-NetLocalGroupMember/)=true OR match_regex(cmd_line, /(?i)Get-NetLoggedon/)=true OR match_regex(cmd_line, /(?i)Get-RegLoggedOn/)=true OR match_regex(cmd_line, /(?i)Get-WMIRegLastLoggedOn/)=true OR match_regex(cmd_line, /(?i)Get-LastLoggedOn/)=true )

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
| 80.0 | 80 | 100 | PowerSploit malware is searching for and using specific accounts, groups and policies, such as the last logged on account, a local Net group, etc. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/reconnaissance_and_access_to_accounts_groups_and_policies_via_powersploit_modules.yml) \| *version*: **1**