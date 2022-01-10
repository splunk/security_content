---
title: "WMI Temporary Event Subscription"
excerpt: "Windows Management Instrumentation"
categories:
  - Endpoint
last_modified_at: 2018-10-23
toc: true
toc_label: ""
tags:
  - Windows Management Instrumentation
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the creation of WMI temporary event subscriptions.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-10-23
- **Author**: Rico Valdez, Splunk
- **ID**: 38cbd42c-1098-41bb-99cf-9d6d2b296d83


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |

#### Search

```
`wmi` EventCode=5860 Temporary 
| rex field=Message "NotificationQuery =\s+(?<query>[^;
|^$]+)" 
| search query!="SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'" AND query!="SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA 'AntiVirusProduct' OR TargetInstance ISA 'FirewallProduct' OR TargetInstance ISA 'AntiSpywareProduct'" 
| stats count min(_time) as firstTime max(_time) as lastTime by ComputerName, query  
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `wmi_temporary_event_subscription_filter`
```

#### Associated Analytic Story
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


#### How To Implement
To successfully implement this search, you must be ingesting the Windows WMI activity logs. This can be done by adding a stanza to inputs.conf on the system generating logs with a title of [WinEventLog://Microsoft-Windows-WMI-Activity/Operational].

#### Required field
* _time
* EventCode
* Message
* query


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Some software may create WMI temporary event subscriptions for various purposes. The included search contains an exception for two of these that occur by default on Windows 10 systems. You may need to modify the search to create exceptions for other legitimate events.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/wmi_temporary_event_subscription.yml) \| *version*: **1**