---
title: "Windows Gather Victim Network Info Through Ip Check Web Services"
excerpt: "IP Addresses
, Gather Victim Network Information
"
categories:
  - Endpoint
last_modified_at: 2022-06-21
toc: true
toc_label: ""
tags:
  - IP Addresses
  - Gather Victim Network Information
  - Reconnaissance
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies process that attempts to connect to a known IP web services. This technique is commonly used by trickbot and other malware to perform reconnaissance against the infected machine and look for its IP address.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 70f7c952-0758-46d6-9148-d8969c4481d1


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1590.005](https://attack.mitre.org/techniques/T1590/005/) | IP Addresses | Reconnaissance |

| [T1590](https://attack.mitre.org/techniques/T1590/) | Gather Victim Network Information | Reconnaissance |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```
`sysmon` EventCode=22  QueryName IN ("*wtfismyip.com", "*checkip.amazonaws.com", "*ipecho.net", "*ipinfo.io", "*api.ipify.org", "*icanhazip.com", "*ip.anysrc.com","*api.ip.sb", "ident.me", "www.myexternalip.com", "*zen.spamhaus.org", "*cbl.abuseat.org", "*b.barracudacentral.org", "*dnsbl-1.uceprotect.net", "*spam.dnsbl.sorbs.net", "*iplogger.org*", "*ip-api.com*") 
|  stats  min(_time) as firstTime max(_time) as lastTime count by  Image ProcessId QueryName QueryStatus QueryResults Computer EventCode 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_gather_victim_network_info_through_ip_check_web_services_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

> :information_source:
> **windows_gather_victim_network_info_through_ip_check_web_services_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Image
* ProcessId
* QueryName
* QueryStatus
* QueryResults
* Computer
* EventCode


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, dns query name process path , and query ststus from your endpoints like EventCode 22. If you are using Sysmon, you must have at least version 12 of the Sysmon TA.

#### Known False Positives
Filter internet browser application to minimize the false positive of this detection.

#### Associated Analytic story
* [Azorult](/stories/azorult)
* [DarkCrystal RAT](/stories/darkcrystal_rat)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | process connecting IP location web services on $Computer$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/](https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_gather_victim_network_info_through_ip_check_web_services.yml) \| *version*: **1**