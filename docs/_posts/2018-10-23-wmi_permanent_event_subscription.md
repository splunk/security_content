---
title: "WMI Permanent Event Subscription"
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
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the creation of WMI permanent event subscriptions.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-10-23
- **Author**: Rico Valdez, Splunk
- **ID**: 71bfdb13-f200-4c6c-b2c9-a2e07adf437d


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |

#### Search

```
`wmi` EventCode=5861 Binding 
| rex field=Message "Consumer =\s+(?<consumer>[^;
|^$]+)" 
| search consumer!="NTEventLogEventConsumer=\"SCM Event Log Consumer\"" 
| stats count min(_time) as firstTime max(_time) as lastTime by ComputerName, consumer, Message 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| rename ComputerName as dest 
| `wmi_permanent_event_subscription_filter`
```

#### Associated Analytic Story
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


#### How To Implement
To successfully implement this search, you must be ingesting the Windows WMI activity logs. This can be done by adding a stanza to inputs.conf on the system generating logs with a title of [WinEventLog://Microsoft-Windows-WMI-Activity/Operational].

#### Required field
* _time
* EventCode
* Message
* consumer
* ComputerName


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Although unlikely, administrators may use event subscriptions for legitimate purposes.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/wmi_permanent_event_subscription.yml) \| *version*: **1**