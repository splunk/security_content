---
title: "Detect WMI Event Subscription Persistence"
excerpt: "Windows Management Instrumentation Event Subscription"
categories:
  - Endpoint
last_modified_at: 2021-06-16
toc: true
tags:
  - TTP
  - T1546.003
  - Windows Management Instrumentation Event Subscription
  - Privilege Escalation
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of WMI Event Subscription to establish persistence or perform privilege escalation.  WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges. This analytic is restricted by commonly added process execution and a path. If the volume is low enough, remove the values and flag on any new subscriptions.\
All event subscriptions have three components \
1. Filter - WQL Query for the events we want. EventID equals 19 \
1. Consumer - An action to take upon triggering the filter. EventID equals 20 \
1. Binding - Registers a filter to a consumer. EventID equals 21 \
Monitor for the creation of new WMI EventFilter, EventConsumer, and FilterToConsumerBinding. It may be pertinent to review all 3 to identify the flow of execution. In addition, EventCode 4104 may assist with any other PowerShell script usage that registered the subscription.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-06-16
- **Author**: Michael Haag, Splunk
- **ID**: 01d9a0c2-cece-11eb-ab46-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | Windows Management Instrumentation Event Subscription | Privilege Escalation, Persistence |


#### Search

```
`sysmon` EventID=20 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer User Destination 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_wmi_event_subscription_persistence_filter`
```

#### Associated Analytic Story
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with that provide WMI Event Subscription from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA and have enabled EventID 19, 20 and 21. Tune and filter known good to limit the volume.

#### Required field
* _time
* Destination
* Computer
* User


#### Kill Chain Phase
* Exploitation


#### Known False Positives
It is possible some applications will create a consumer and may be required to be filtered. For tuning, add any additional LOLBin&#39;s for further depth of coverage.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | Possible malicious WMI Subscription created on $dest$ |



#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md)
* [https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)
* [https://github.com/trustedsec/SysmonCommunityGuide/blob/master/WMI-events.md](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/WMI-events.md)
* [https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/](https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.003/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.003/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_wmi_event_subscription_persistence.yml) \| *version*: **1**