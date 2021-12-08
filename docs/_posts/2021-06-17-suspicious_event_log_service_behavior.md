---
title: "Suspicious Event Log Service Behavior"
excerpt: "Indicator Removal on Host, Clear Windows Event Logs"
categories:
  - Endpoint
last_modified_at: 2021-06-17
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

The following analytic utilizes Windows Event ID 1100 to identify when Windows event log service is shutdown. Note that this is a voluminous analytic that will require tuning or restricted to specific endpoints based on criticality. This event generates every time Windows Event Log service has shut down. It also generates during normal system shutdown. During triage, based on time of day and user, determine if this was planned. If not planned, follow through with reviewing parallel alerts and other data sources to determine what else may have occurred.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-06-17
- **Author**: Mauricio Velazco, Splunk
- **ID**: 2b85aa3d-f5f6-4c2e-a081-a09f6e1c2e40


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Defense Evasion |

| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | Defense Evasion |

#### Search

```
(`wineventlog_security` EventCode=1100) 
| stats count min(_time) as firstTime max(_time) as lastTime by dest Message EventCode 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_event_log_service_behavior_filter`
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
It is possible the Event Logging service gets shut down due to system errors or legitimately administration tasks. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | The Windows Event Log Service shutdown on $ComputerName$ |




#### Reference

* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1100](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1100)
* [https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads](https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads)
* [https://attack.mitre.org/techniques/T1070/001/](https://attack.mitre.org/techniques/T1070/001/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/atomic_red_team/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_event_log_service_behavior.yml) \| *version*: **1**