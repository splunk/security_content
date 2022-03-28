---
title: "WMI Permanent Event Subscription"
excerpt: "Windows Management Instrumentation
"
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

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the creation of WMI permanent event subscriptions.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2018-10-23
- **Author**: Rico Valdez, Splunk
- **ID**: 71bfdb13-f200-4c6c-b2c9-a2e07adf437d


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
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

#### Macros
The SPL above uses the following Macros:
* [wmi](https://github.com/splunk/security_content/blob/develop/macros/wmi.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `wmi_permanent_event_subscription_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Message
* consumer
* ComputerName


#### How To Implement
To successfully implement this search, you must be ingesting the Windows WMI activity logs. This can be done by adding a stanza to inputs.conf on the system generating logs with a title of [WinEventLog://Microsoft-Windows-WMI-Activity/Operational].

#### Known False Positives
Although unlikely, administrators may use event subscriptions for legitimate purposes.

#### Associated Analytic story
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/wmi_permanent_event_subscription.yml) \| *version*: **1**