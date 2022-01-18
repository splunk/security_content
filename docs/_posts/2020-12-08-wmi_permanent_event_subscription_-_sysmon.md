---
title: "WMI Permanent Event Subscription - Sysmon"
excerpt: "Windows Management Instrumentation Event Subscription, Event Triggered Execution"
categories:
  - Endpoint
last_modified_at: 2020-12-08
toc: true
toc_label: ""
tags:
  - Windows Management Instrumentation Event Subscription
  - Privilege Escalation
  - Persistence
  - Event Triggered Execution
  - Privilege Escalation
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for the creation of WMI permanent event subscriptions. The following analytic identifies the use of WMI Event Subscription to establish persistence or perform privilege escalation.  WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges. This analytic is restricted by commonly added process execution and a path. If the volume is low enough, remove the values and flag on any new subscriptions.\
All event subscriptions have three components \
1. Filter - WQL Query for the events we want. EventID = 19 \
1. Consumer - An action to take upon triggering the filter. EventID = 20 \
1. Binding - Registers a filter to a consumer. EventID = 21 \
Monitor for the creation of new WMI EventFilter, EventConsumer, and FilterToConsumerBinding. It may be pertinent to review all 3 to identify the flow of execution. In addition, EventCode 4104 may assist with any other PowerShell script usage that registered the subscription.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-12-08
- **Author**: Rico Valdez, Michael Haag, Splunk
- **ID**: ad05aae6-3b2a-4f73-af97-57bd26cee3b9


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | Windows Management Instrumentation Event Subscription | Privilege Escalation, Persistence |

| [T1546](https://attack.mitre.org/techniques/T1546/) | Event Triggered Execution | Privilege Escalation, Persistence |

#### Search

```
`sysmon` EventCode=21 
| rename host as dest 
| table _time, dest, user, Operation, EventType, Query, Consumer, Filter 
| `wmi_permanent_event_subscription___sysmon_filter`
```

#### Associated Analytic Story
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


#### How To Implement
To successfully implement this search, you must be collecting Sysmon data using Sysmon version 6.1 or greater and have Sysmon configured to generate alerts for WMI activity (eventID= 19, 20, 21). In addition, you must have at least version 6.0.4 of the Sysmon TA installed to properly parse the fields.

#### Required field
* _time
* EventCode
* host
* user
* Operation
* EventType
* Query
* Consumer
* Filter


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Although unlikely, administrators may use event subscriptions for legitimate purposes.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 30 | 100 | User $user$ on $host$ executed the following suspicious WMI query: $Query$.  Filter: $filter$. Consumer: $Consumer$.  EventCode: $EventCode$ |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md)
* [https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)
* [https://github.com/trustedsec/SysmonCommunityGuide/blob/master/WMI-events.md](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/WMI-events.md)
* [https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/](https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.003/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.003/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wmi_permanent_event_subscription_-_sysmon.yml) \| *version*: **3**