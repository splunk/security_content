---
title: "Excessive Usage of NSLOOKUP App"
excerpt: "Exfiltration Over Alternative Protocol
"
categories:
  - Endpoint
last_modified_at: 2021-04-21
toc: true
toc_label: ""
tags:
  - Exfiltration Over Alternative Protocol
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect potential DNS exfiltration using nslookup application. This technique are seen in couple of malware and APT group to exfiltrated collected data in a infected machine or infected network. This detection is looking for unique use of nslookup where it tries to use specific record type (TXT, A, AAAA) that are commonly used by attacker and also the retry parameter which is designed to query C2 DNS multiple tries.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-04-21
- **Author**: Teoderick Contreras, Stanislav Miskovic, Splunk
- **ID**: 0a69fdaa-a2b8-11eb-b16d-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Exfiltration |

#### Search

```
`sysmon` EventCode = 1 process_name = "nslookup.exe" 
|  bucket _time span=15m 
| stats count as numNsLookup by Computer, _time 
|  eventstats avg(numNsLookup) as avgNsLookup, stdev(numNsLookup) as stdNsLookup, count as numSlots by Computer 
|  eval upperThreshold=(avgNsLookup + stdNsLookup *3) 
|  eval isOutlier=if(avgNsLookup > 20 and avgNsLookup >= upperThreshold, 1, 0) 
|  search isOutlier=1 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `excessive_usage_of_nslookup_app_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `excessive_usage_of_nslookup_app_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Computer
* process_name
* EventCode


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances of nslookup.exe may be used.

#### Known False Positives
unknown

#### Associated Analytic story
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Dynamic DNS](/stories/dynamic_dns)
* [Data Exfiltration](/stories/data_exfiltration)
* [Command and Control](/stories/command_and_control)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 28.0 | 40 | 70 | Excessive usage of nslookup.exe has been detected on $Computer$. This detection is triggered as as it violates the dynamic threshold |




#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html](https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html)
* [https://www.varonis.com/blog/dns-tunneling/](https://www.varonis.com/blog/dns-tunneling/)
* [https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/nslookup_exfil/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/nslookup_exfil/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/excessive_usage_of_nslookup_app.yml) \| *version*: **1**