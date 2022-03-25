---
title: "Rundll32 DNSQuery"
excerpt: "Signed Binary Proxy Execution
, Rundll32
"
categories:
  - Endpoint
last_modified_at: 2022-02-18
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Rundll32
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious rundll32.exe process having a http connection and do a dns query in some web domain. This technique was seen in IcedID malware where the rundll32 that execute its payload will contact amazon.com to check internet connect and to communicate to its C&C server to download config and other file component.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-02-18
- **Author**: Teoderick Contreras, Splunk
- **ID**: f1483f5e-ee29-11eb-9d23-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | Defense Evasion |

#### Search

```
`sysmon` EventCode=22 process_name="rundll32.exe" 
| stats count min(_time) as firstTime max(_time) as lastTime by Image QueryName QueryStatus ProcessId  Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `rundll32_dnsquery_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `rundll32_dnsquery_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Image
* QueryName
* QueryStatus
* ProcessId
* Computer


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and eventcode = 22 dnsquery executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed rundll32.exe may be used.

#### Known False Positives
unknown

#### Associated Analytic story
* [IcedID](/stories/icedid)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | rundll32 process $process_name$ having a dns query to $QueryName$ in host $Computer$ |




#### Reference

* [https://any.run/malware-trends/icedid](https://any.run/malware-trends/icedid)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/rundll32_dnsquery.yml) \| *version*: **2**