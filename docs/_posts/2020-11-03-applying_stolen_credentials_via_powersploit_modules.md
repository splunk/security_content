---
title: "Applying Stolen Credentials via PowerSploit modules"
excerpt: "Process Injection, Exploitation for Privilege Escalation, Valid Accounts, Account Manipulation, Access Token Manipulation, Create or Modify System Process, Boot or Logon Autostart Execution, Abuse Elevation Control Mechanism, Compromise Client Software Binary, Credentials from Password Stores, Steal or Forge Kerberos Tickets"
categories:
  - Endpoint
last_modified_at: 2020-11-03
toc: true
toc_label: ""
tags:
  - Process Injection
  - Defense Evasion
  - Privilege Escalation
  - Exploitation for Privilege Escalation
  - Privilege Escalation
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Account Manipulation
  - Persistence
  - Access Token Manipulation
  - Defense Evasion
  - Privilege Escalation
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - Abuse Elevation Control Mechanism
  - Privilege Escalation
  - Defense Evasion
  - Compromise Client Software Binary
  - Persistence
  - Credentials from Password Stores
  - Credential Access
  - Steal or Forge Kerberos Tickets
  - Credential Access
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Stolen credentials are applied by methods such as user impersonation, credential injection, spoofing of authentication processes or getting hold of critical accounts. This detection indicates such activities carried out by PowerSploit exploit kit APIs.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-03
- **Author**: Stanislav Miskovic, Splunk
- **ID**: 270b482d-2af2-448f-9923-9cf005f61be4


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1055](https://attack.mitre.org/techniques/T1055/) | Process Injection | Defense Evasion, Privilege Escalation |

| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation |

| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |

| [T1134](https://attack.mitre.org/techniques/T1134/) | Access Token Manipulation | Defense Evasion, Privilege Escalation |

| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

| [T1554](https://attack.mitre.org/techniques/T1554/) | Compromise Client Software Binary | Persistence |

| [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores | Credential Access |

| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Invoke-CredentialInjection/)=true OR match_regex(cmd_line, /(?i)Invoke-TokenManipulation/)=true OR match_regex(cmd_line, /(?i)Invoke-UserImpersonation/)=true OR match_regex(cmd_line, /(?i)Get-System/)=true OR match_regex(cmd_line, /(?i)Invoke-RevertToSelf/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


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

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | PowerSploit malware is violating authentication by injecting stolen credentials, manipulating authentication tokens or impersonating system or user accounts. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/applying_stolen_credentials/logAllPowerSploitModulesWithOldNames.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/applying_stolen_credentials/logAllPowerSploitModulesWithOldNames.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/applying_stolen_credentials_via_powersploit_modules.yml) \| *version*: **1**