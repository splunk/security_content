---
title: "Credential Extraction indicative of use of PowerSploit modules"
excerpt: "OS Credential Dumping"
categories:
  - Endpoint
last_modified_at: 2020-10-21
toc: true
tags:
  - TTP
  - T1003
  - OS Credential Dumping
  - Credential Access
  - Splunk Behavioral Analytics
  - Actions on Objectives
---

#### Description

Credential extraction is often an illegal recovery of credential material from secured authentication resources and repositories. This process may also involve decryption or other transformations of the stored credential material. PowerSploit is a collection of Microsoft PowerShell modules commonly employed in exploits.

- **Product**: Splunk Behavioral Analytics
- **Datamodel**:
- **Last Updated**: 2020-10-21
- **Author**: Stanislav Miskovic, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |


#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Get-ApplicationHost/)=true OR match_regex(cmd_line, /(?i)Get-CachedGPPPassword/)=true OR match_regex(cmd_line, /(?i)Get-GPPAutologon/)=true OR match_regex(cmd_line, /(?i)Get-GPPPassword/)=true OR match_regex(cmd_line, /(?i)Get-RegistryAutoLogon/)=true OR match_regex(cmd_line, /(?i)Get-SiteListPassword/)=true OR match_regex(cmd_line, /(?i)Get-SPNTicket/)=true OR match_regex(cmd_line, /(?i)Request-SPNTicket/)=true OR match_regex(cmd_line, /(?i)Get-VaultCredential/)=true OR match_regex(cmd_line, /(?i)Invoke-Kerberoast/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
* [Credential Dumping](_stories/credential_dumping)
* [Malicious PowerShell](_stories/malicious_powershell)


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
| 70.0 | 70 | 100 |



#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllPowerSploitModulesWithOldNames.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/logAllPowerSploitModulesWithOldNames.log)


_version_: 1