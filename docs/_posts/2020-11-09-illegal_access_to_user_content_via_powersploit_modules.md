---
title: "Illegal Access To User Content via PowerSploit modules"
excerpt: "Remote Services, Screen Capture, Audio Capture, Remote Service Session Hijacking"
categories:
  - Endpoint
last_modified_at: 2020-11-09
toc: true
tags:
  - TTP
  - T1021
  - Remote Services
  - Lateral Movement
  - T1113
  - Screen Capture
  - Collection
  - T1123
  - Audio Capture
  - Collection
  - T1563
  - Remote Service Session Hijacking
  - Lateral Movement
  - Splunk Behavioral Analytics
  - Actions on Objectives
---

#### Description

This detection identifies access to PowerSploit modules that enable illegaly access user content, such as key logging, audio recording, screenshots, tapping into http and RDP sessions, etc.

- **Product**: Splunk Behavioral Analytics
- **Datamodel**:
- **Last Updated**: 2020-11-09
- **Author**: Stanislav Miskovic, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement || [T1113](https://attack.mitre.org/techniques/T1113/) | Screen Capture | Collection || [T1123](https://attack.mitre.org/techniques/T1123/) | Audio Capture | Collection || [T1563](https://attack.mitre.org/techniques/T1563/) | Remote Service Session Hijacking | Lateral Movement |


#### Search

```

| from read_ssa_enriched_events()

| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line != null AND ( match_regex(cmd_line, /(?i)Get-HttpStatus/)=true OR match_regex(cmd_line, /(?i)Get-Keystrokes/)=true OR match_regex(cmd_line, /(?i)Get-MicrophoneAudio/)=true OR match_regex(cmd_line, /(?i)Get-NetRDPSession/)=true OR match_regex(cmd_line, /(?i)Get-TimedScreenshot/)=true OR match_regex(cmd_line, /(?i)Get-WebConfig/)=true )

| eval start_time = timestamp, end_time = timestamp, entities = mvappend( ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story
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
| 85.0 | 85 | 100 |



#### Reference

* [https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021/illegal_access_to_content/logAllPowerSploitModulesWithOldNames.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021/illegal_access_to_content/logAllPowerSploitModulesWithOldNames.log)


_version_: 1