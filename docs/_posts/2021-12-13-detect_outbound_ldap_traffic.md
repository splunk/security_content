---
title: "Detect Outbound LDAP Traffic"
excerpt: "Exploit Public-Facing Application
, Command and Scripting Interpreter
"
categories:
  - Network
last_modified_at: 2021-12-13
toc: true
toc_label: ""
tags:

  - Exploit Public-Facing Application
  - Command and Scripting Interpreter
  - Initial Access
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Malicious actors often abuse misconfigured LDAP servers or applications that use the LDAP servers in organizations. Outbound LDAP traffic should not be allowed outbound through your perimeter firewall.  This search will help determine if you have any LDAP connections to IP addresses outside of private (RFC1918) address space.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-12-13
- **Author**: Bhavin Patel, Johan Bjerke, Splunk
- **ID**: 5e06e262-d7cd-4216-b2f8-27b437e18458


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

#### Search

```

| tstats earliest(_time) as earliest_time latest(_time) as latest_time values(All_Traffic.dest_ip) as dest_ip from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port = 389 OR All_Traffic.dest_port = 636 AND NOT (All_Traffic.dest_ip = 10.0.0.0/8 OR All_Traffic.dest_ip=192.168.0.0/16 OR All_Traffic.dest_ip = 172.16.0.0/12) by All_Traffic.src_ip All_Traffic.dest_ip 
|`drop_dm_object_name("All_Traffic")` 
| where src_ip != dest_ip 
| `security_content_ctime(latest_time)`  
| `security_content_ctime(earliest_time)` 
|`detect_outbound_ldap_traffic_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `detect_outbound_ldap_traffic_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.dest_ip
* All_Traffic.dest_port
* All_Traffic.src_ip


#### How To Implement
You must be ingesting Zeek DNS and Zeek Conn data into Splunk. Zeek data should also be getting ingested in JSON format and should be mapped to the Network Traffic datamodels that are in use for this search.

#### Known False Positives
Unknown at this moment. Outbound LDAP traffic should not be allowed outbound through your perimeter firewall. Please check those servers to verify if the activity is legitimate.

#### Associated Analytic story
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)


#### Kill Chain Phase
* Command and Control
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | An outbound LDAP connection from $src_ip$ in your infrastructure connecting to dest ip $dest_ip$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/](https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/outbound_ldap/bro_conn.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/outbound_ldap/bro_conn.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/network/detect_outbound_ldap_traffic.yml) \| *version*: **1**