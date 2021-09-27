---
title: "Wermgr Process Connecting To IP Check Web Services"
excerpt: "IP Addresses"
categories:
  - Endpoint
last_modified_at: 2021-04-19
toc: true
tags:
  - TTP
  - T1590.005
  - IP Addresses
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

this search is designed to detect suspicious wermgr.exe process that tries to connect to known IP web services. This technique is know for trickbot and other trojan spy malware to recon the infected machine and look for its ip address without so much finger print on the commandline process. Since wermgr.exe is designed for error handling process of windows it is really suspicious that this process is trying to connect to this IP web services cause that maybe cause of some malicious code injection.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: ed313326-a0f9-11eb-a89c-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1590.005](https://attack.mitre.org/techniques/T1590/005/) | IP Addresses | Reconnaissance |


#### Search

```
`sysmon` EventCode =22 process_name = wermgr.exe QueryName IN ("*wtfismyip.com", "*checkip.amazonaws.com", "*ipecho.net", "*ipinfo.io", "*api.ipify.org", "*icanhazip.com", "*ip.anysrc.com","*api.ip.sb", "ident.me", "www.myexternalip.com", "*zen.spamhaus.org", "*cbl.abuseat.org", "*b.barracudacentral.org","*dnsbl-1.uceprotect.net", "*spam.dnsbl.sorbs.net") 
|  stats  min(_time) as firstTime max(_time) as lastTime count by  process_path process_name process_id QueryName QueryStatus QueryResults Computer EventCode 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wermgr_process_connecting_to_ip_check_web_services_filter`
```

#### Associated Analytic Story
* [Trickbot](/stories/trickbot)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, dns query name process path , and query ststus from your endpoints like EventCode 22. If you are using Sysmon, you must have at least version 12 of the Sysmon TA.

#### Required field
* _time
* process_path
* process_name
* process_id
* QueryName
* QueryStatus
* QueryResults
* Computer
* EventCode


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | Wermgr.exe process connecting IP location web services on $ComputerName$ |



#### Reference

* [https://labs.vipre.com/trickbot-and-its-modules/](https://labs.vipre.com/trickbot-and-its-modules/)
* [https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html](https://blog.whitehat.eu/2019/05/incident-trickbot-ryuk-2.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wermgr_process_connecting_to_ip_check_web_services.yml) \| *version*: **1**