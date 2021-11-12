---
title: "Reconnaissance and Access to Active Directoty Infrastructure via PowerSploit modules"
excerpt: "Trusted Relationship, Domain Trust Discovery, Gather Victim Network Information, Gather Victim Org Information, Active Scanning"
categories:
  - Endpoint
last_modified_at: 2020-11-06
toc: true
toc_label: ""
tags:
  - Trusted Relationship
  - Initial Access
  - Domain Trust Discovery
  - Discovery
  - Gather Victim Network Information
  - Reconnaissance
  - Gather Victim Org Information
  - Reconnaissance
  - Active Scanning
  - Reconnaissance
  - Splunk Behavioral Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies access to PowerSploit modules for reconnaissance and access to elements of Active Directory infrastructure, such as domain identifiers, AD sites and forests, and trust relations.

- **Type**: TTP
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-11-06
- **Author**: Stanislav Miskovic, Splunk
- **ID**: db08ac40-ee14-43e9-9a75-dddd059ef812


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1199](https://attack.mitre.org/techniques/T1199/) | Trusted Relationship | Initial Access |

| [T1482](https://attack.mitre.org/techniques/T1482/) | Domain Trust Discovery | Discovery |

| [T1590](https://attack.mitre.org/techniques/T1590/) | Gather Victim Network Information | Reconnaissance |

| [T1591](https://attack.mitre.org/techniques/T1591/) | Gather Victim Org Information | Reconnaissance |

| [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning | Reconnaissance |

#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Get-DomainSID/)=true OR match_regex(cmd_line, /(?i)Get-DomainSite/)=true OR match_regex(cmd_line, /(?i)Get-NetSite/)=true OR match_regex(cmd_line, /(?i)Get-DomainSubnet/)=true OR match_regex(cmd_line, /(?i)Get-NetSubnet/)=true OR match_regex(cmd_line, /(?i)Get-DomainTrust/)=true OR match_regex(cmd_line, /(?i)Get-NetDomainTrust/)=true OR match_regex(cmd_line, /(?i)Get-DomainTrustMapping/)=true OR match_regex(cmd_line, /(?i)Invoke-MapDomainTrust/)=true OR match_regex(cmd_line, /(?i)Get-Forest/)=true OR match_regex(cmd_line, /(?i)Get-NetForest/)=true OR match_regex(cmd_line, /(?i)Get-ForestDomain/)=true OR match_regex(cmd_line, /(?i)Get-NetForestDomain/)=true OR match_regex(cmd_line, /(?i)Get-ForestGlobalCatalog/)=true OR match_regex(cmd_line, /(?i)Get-NetForestCatalog/)=true OR match_regex(cmd_line, /(?i)Get-ForestTrust/)=true OR match_regex(cmd_line, /(?i)Get-NetForestTrust/)=true )

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
| 80.0 | 80 | 100 | PowerSploit malware is seaching for or accessing Active Directory objects such as domain sites, domain trusts, AD forests, etc. Operation is performed at the device $dest_device_id$, by the account $dest_user_id$ via command $cmd_line$ |




#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/reconnaissance_and_access_to_active_directoty_infrastructure_via_powersploit_modules.yml) \| *version*: **1**