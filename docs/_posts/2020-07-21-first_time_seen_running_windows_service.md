---
title: "First Time Seen Running Windows Service"
excerpt: "System Services, Service Execution"
categories:
  - Endpoint
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - System Services
  - Execution
  - Service Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for the first and last time a Windows service is seen running in your environment. This table is then cached.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-21
- **Author**: David Dorsey, Splunk
- **ID**: 823136f2-d755-4b6d-ae04-372b486a5808


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1569](https://attack.mitre.org/techniques/T1569/) | System Services | Execution |

| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | Execution |

#### Search

```
`wineventlog_system` EventCode=7036 
| rex field=Message "The (?<service>[-\(\)\s\w]+) service entered the (?<state>\w+) state" 
| where state="running" 
| lookup previously_seen_running_windows_services service as service OUTPUT firstTimeSeen 
| where isnull(firstTimeSeen) OR firstTimeSeen > relative_time(now(), `previously_seen_windows_services_window`) 
| table _time dest service 
| `first_time_seen_running_windows_service_filter`
```

#### Associated Analytic Story
* [Windows Service Abuse](/stories/windows_service_abuse)
* [Orangeworm Attack Group](/stories/orangeworm_attack_group)
* [NOBELIUM Group](/stories/nobelium_group)


#### How To Implement
While this search does not require you to adhere to Splunk CIM, you must be ingesting your Windows system event logs in order for this search to execute successfully. You should run the baseline search `Previously Seen Running Windows Services - Initial` to build the initial table of child processes and hostnames for this search to work. You should also schedule at the same interval as this search the second baseline search `Previously Seen Running Windows Services - Update` to keep this table up to date and to age out old Windows Services. Please update the `previously_seen_windows_services_window` macro to adjust the time window. Please ensure that the Splunk Add-on for Microsoft Windows is version 8.0.0 or above.

#### Required field
* _time
* EventCode
* Message
* dest


#### Kill Chain Phase
* Installation
* Actions on Objectives


#### Known False Positives
A previously unseen service is not necessarily malicious. Verify that the service is legitimate and that was installed by a legitimate process.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/first_time_seen_running_windows_service.yml) \| *version*: **4**