---
title: "Windows Event Log Cleared"
excerpt: "Indicator Removal on Host, Clear Windows Event Logs"
categories:
  - Endpoint
last_modified_at: 2020-07-06
toc: true
toc_label: ""
tags:
  - Indicator Removal on Host
  - Defense Evasion
  - Clear Windows Event Logs
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes Windows Security Event ID 1102 or System log event 104 to identify when a Windows event log is cleared. Note that this analytic will require tuning or restricted to specific endpoints based on criticality. During triage, based on time of day and user, determine if this was planned. If not planned, follow through with reviewing parallel alerts and other data sources to determine what else may have occurred.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-06
- **Author**: Rico Valdez, Michael Haag, Splunk
- **ID**: ad517544-aff9-4c96-bd99-d6eb43bfbb6a


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | Defense Evasion |

#### Search

```
(`wineventlog_security` EventCode=1102) OR (`wineventlog_system` EventCode=104) 
| stats count min(_time) as firstTime max(_time) as lastTime by dest Message EventCode 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_event_log_cleared_filter`
```

#### Associated Analytic Story
* [Windows Log Manipulation](/stories/windows_log_manipulation)
* [Ransomware](/stories/ransomware)
* [Clop Ransomware](/stories/clop_ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting Windows event logs from your hosts. In addition, the Splunk Windows TA is needed.

#### Required field
* _time
* EventCode
* dest


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
It is possible that these logs may be legitimately cleared by Administrators. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | Windows event logs cleared on $dest$ via EventCode $EventCode$ |




#### Reference

* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)
* [https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads](https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads)
* [https://attack.mitre.org/techniques/T1070/001/](https://attack.mitre.org/techniques/T1070/001/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-security.log)
* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-system.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_event_log_cleared.yml) \| *version*: **6**