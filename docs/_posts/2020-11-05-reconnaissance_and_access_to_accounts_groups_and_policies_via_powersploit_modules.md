---
title: "Reconnaissance and Access to Accounts Groups and Policies via PowerSploit modules"
excerpt: "Valid Accounts, Account Discovery, Domain Policy Modification"
categories:
  - Endpoint
last_modified_at: 2020-11-05
toc: true
tags:
  - TTP
  - T1078
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - T1087
  - Account Discovery
  - Discovery
  - T1484
  - Domain Policy Modification
  - Defense Evasion
  - Privilege Escalation
  - Splunk Behavioral Analytics
  - Actions on Objectives
---

# Reconnaissance and Access to Accounts Groups and Policies via PowerSploit modules

This detection identifies access to PowerSploit modules that discover accounts, groups and policies that can be accessed or taken over.

- **Product**: Splunk Behavioral Analytics
- **Datamodel**:
- **ATT&CK**: [T1078](https://attack.mitre.org/techniques/T1078/), [T1087](https://attack.mitre.org/techniques/T1087/), [T1484](https://attack.mitre.org/techniques/T1484/)
- **Last Updated**: 2020-11-05
- **Author**: Stanislav Miskovic, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1087 | Account Discovery | Discovery |
| T1484 | Domain Policy Modification | Defense Evasion, Privilege Escalation |


#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, &#34;_time&#34;), &#34;string&#34;, null)), cmd_line=ucast(map_get(input_event, &#34;process&#34;), &#34;string&#34;, null), event_id=ucast(map_get(input_event, &#34;event_id&#34;), &#34;string&#34;, null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Find-DomainLocalGroupMember/)=true OR match_regex(cmd_line, /(?i)Invoke-EnumerateLocalAdmin/)=true OR match_regex(cmd_line, /(?i)Find-DomainUserEvent/)=true OR match_regex(cmd_line, /(?i)Invoke-EventHunter/)=true OR match_regex(cmd_line, /(?i)Find-DomainUserLocation/)=true OR match_regex(cmd_line, /(?i)Invoke-UserHunter/)=true OR match_regex(cmd_line, /(?i)Get-DomainForeignGroupMember/)=true OR match_regex(cmd_line, /(?i)Find-ForeignGroup/)=true OR match_regex(cmd_line, /(?i)Get-DomainForeignUser/)=true OR match_regex(cmd_line, /(?i)Find-ForeignUser/)=true OR match_regex(cmd_line, /(?i)Get-DomainGPO/)=true OR match_regex(cmd_line, /(?i)Get-NetGPO/)=true OR match_regex(cmd_line, /(?i)Get-DomainGPOComputerLocalGroupMapping/)=true OR match_regex(cmd_line, /(?i)Find-GPOComputerAdmin/)=true OR match_regex(cmd_line, /(?i)Get-DomainGPOLocalGroup/)=true OR match_regex(cmd_line, /(?i)Get-NetGPOGroup/)=true OR match_regex(cmd_line, /(?i)Get-DomainGPOUserLocalGroupMapping/)=true OR match_regex(cmd_line, /(?i)Find-GPOLocation/)=true OR match_regex(cmd_line, /(?i)Get-DomainGroup/)=true OR match_regex(cmd_line, /(?i)Get-NetGroup/)=true OR match_regex(cmd_line, /(?i)Get-DomainGroupMember/)=true OR match_regex(cmd_line, /(?i)Get-NetGroupMember/)=true OR match_regex(cmd_line, /(?i)Get-DomainManagedSecurityGroup/)=true OR match_regex(cmd_line, /(?i)Find-ManagedSecurityGroups/)=true OR match_regex(cmd_line, /(?i)Get-DomainOU/)=true OR match_regex(cmd_line, /(?i)Get-NetOU/)=true OR match_regex(cmd_line, /(?i)Get-DomainUser/)=true OR match_regex(cmd_line, /(?i)Get-NetUser/)=true OR match_regex(cmd_line, /(?i)Get-DomainUserEvent/)=true OR match_regex(cmd_line, /(?i)Get-UserEvent/)=true OR match_regex(cmd_line, /(?i)Get-NetLocalGroup/)=true OR match_regex(cmd_line, /(?i)Get-NetLocalGroupMember/)=true OR match_regex(cmd_line, /(?i)Get-NetLoggedon/)=true OR match_regex(cmd_line, /(?i)Get-RegLoggedOn/)=true OR match_regex(cmd_line, /(?i)Get-WMIRegLastLoggedOn/)=true OR match_regex(cmd_line, /(?i)Get-LastLoggedOn/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, &#34;dest_user_id&#34;), &#34;string&#34;, null), ucast(map_get(input_event, &#34;dest_device_id&#34;), &#34;string&#34;, null)), body=create_map([&#34;event_id&#34;, event_id,  &#34;cmd_line&#34;, cmd_line]) 
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
| 80.0 | 80 | 100 |



#### Reference


* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1

```
#############
# Automatically generated by doc_gen.py in https://github.com/splunk/security_content''
# On Date: 2021-09-17 11:18:22.158534 UTC''
# Author: Splunk Security Research''
# Contact: research@splunk.com''
#############
```