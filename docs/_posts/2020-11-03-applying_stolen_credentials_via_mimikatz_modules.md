---
title: "Applying Stolen Credentials via Mimikatz modules"
excerpt: "Process Injection, Exploitation for Privilege Escalation, Valid Accounts, Account Manipulation, Access Token Manipulation, Create or Modify System Process, Boot or Logon Autostart Execution, Abuse Elevation Control Mechanism, Compromise Client Software Binary, Modify Authentication Process, Steal or Forge Kerberos Tickets"
categories:
  - Endpoint
last_modified_at: 2020-11-03
toc: true
tags:
  - TTP
  - T1055
  - Process Injection
  - Defense Evasion
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
  - T1098
  - Account Manipulation
  - Persistence
  - T1134
  - Access Token Manipulation
  - Defense Evasion
  - Privilege Escalation
  - T1543
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - T1547
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - T1548
  - Abuse Elevation Control Mechanism
  - Privilege Escalation
  - Defense Evasion
  - T1554
  - Compromise Client Software Binary
  - Persistence
  - T1556
  - Modify Authentication Process
  - Credential Access
  - Defense Evasion
  - Persistence
  - T1558
  - Steal or Forge Kerberos Tickets
  - Credential Access
  - Splunk Behavioral Analytics
  - Actions on Objectives
---

# Applying Stolen Credentials via Mimikatz modules

This detection indicates use of Mimikatz modules that facilitate Pass-the-Token attack, Golden or Silver kerberos ticket attack, and Skeleton key attack.

- **Product**: Splunk Behavioral Analytics
- **Datamodel**:
- **ATT&CK**: [T1055](https://attack.mitre.org/techniques/T1055/), [T1068](https://attack.mitre.org/techniques/T1068/), [T1078](https://attack.mitre.org/techniques/T1078/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1134](https://attack.mitre.org/techniques/T1134/), [T1543](https://attack.mitre.org/techniques/T1543/), [T1547](https://attack.mitre.org/techniques/T1547/), [T1548](https://attack.mitre.org/techniques/T1548/), [T1554](https://attack.mitre.org/techniques/T1554/), [T1556](https://attack.mitre.org/techniques/T1556/), [T1558](https://attack.mitre.org/techniques/T1558/)
- **Last Updated**: 2020-11-03
- **Author**: Stanislav Miskovic, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| T1098 | Account Manipulation | Persistence |
| T1134 | Access Token Manipulation | Defense Evasion, Privilege Escalation |
| T1543 | Create or Modify System Process | Persistence, Privilege Escalation |
| T1547 | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |
| T1554 | Compromise Client Software Binary | Persistence |
| T1556 | Modify Authentication Process | Credential Access, Defense Evasion, Persistence |
| T1558 | Steal or Forge Kerberos Tickets | Credential Access |


#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, &#34;_time&#34;), &#34;string&#34;, null)), cmd_line=ucast(map_get(input_event, &#34;process&#34;), &#34;string&#34;, null), event_id=ucast(map_get(input_event, &#34;event_id&#34;), &#34;string&#34;, null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)kerberos::ptt/)=true OR match_regex(cmd_line, /(?i)kerberos::golden/)=true OR match_regex(cmd_line, /(?i)kerberos::silver/)=true OR match_regex(cmd_line, /(?i)misc::skeleton/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, &#34;dest_user_id&#34;), &#34;string&#34;, null), ucast(map_get(input_event, &#34;dest_device_id&#34;), &#34;string&#34;, null)), body=create_map([&#34;event_id&#34;, event_id, &#34;cmd_line&#34;, cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story

* [Credential Dumping](_stories/credential_dumping)


#### How To Implement
You must be ingesting Windows Security logs from devices of interest, including the event ID 4688 with enabled command line logging.

#### Required field

* dest_device_id

* dest_user_id

* process

* _time


#### Kill Chain Phase

* Actions on Objectives


#### Known False Positives
None identified.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 90.0 | 90 | 100 |



#### Reference


* [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

* [https://adsecurity.org/?p=1275](https://adsecurity.org/?p=1275)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/applying_stolen_credentials/logAllMimikatzModules.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/applying_stolen_credentials/logAllMimikatzModules.log)


_version_: 1

```
#############
# Automatically generated by doc_gen.py in https://github.com/splunk/security_content''
# On Date: 2021-09-17 11:18:21.939192 UTC''
# Author: Splunk Security Research''
# Contact: research@splunk.com''
#############
```