---
title: "Sunburst Correlation DLL and Network Event"
excerpt: "Exploitation for Client Execution"
categories:
  - Endpoint
last_modified_at: 2020-12-14
toc: true
tags:
  - TTP
  - T1203
  - Exploitation for Client Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The malware sunburst will load the malicious dll by SolarWinds.BusinessLayerHost.exe. After a period of 12-14 days, the malware will attempt to resolve a subdomain of avsvmcloud.com. This detections will correlate both events.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-12-14
- **Author**: Patrick Bareiss, Splunk
- **ID**: 701a8740-e8db-40df-9190-5516d3819787


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation for Client Execution | Execution |



#### Search

```
(`sysmon` EventCode=7 ImageLoaded=*SolarWinds.Orion.Core.BusinessLayer.dll) OR (`sysmon` EventCode=22 QueryName=*avsvmcloud.com) 
| eventstats dc(EventCode) AS dc_events 
| where dc_events=2 
| stats min(_time) as firstTime max(_time) as lastTime values(ImageLoaded) AS ImageLoaded values(QueryName) AS QueryName by host 
| rename host as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `sunburst_correlation_dll_and_network_event_filter` 
```

#### Associated Analytic Story
* [NOBELIUM Group](/stories/nobelium_group)


#### How To Implement
This detection relies on sysmon logs with the Event ID 7, Driver loaded. Please tune your sysmon config that you DriverLoad event for SolarWinds.Orion.Core.BusinessLayer.dll is captured by Sysmon. Additionally, you need sysmon logs for Event ID 22, DNS Query. We suggest to run this detection at least once a day over the last 14 days.

#### Required field
* _time
* EventCode
* ImageLoaded
* QueryName


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
unknown




#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/sunburst_correlation_dll_and_network_event.yml) \| *version*: **1**