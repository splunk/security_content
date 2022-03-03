---
title: "TCP Command and Scripting Interpreter Outbound LDAP Traffic"
excerpt: "Command and Scripting Interpreter"
categories:
  - Network
last_modified_at: 2022-02-17
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Malicious actors often abuse misconfigured LDAP servers or applications that use the LDAP servers in organizations. Outbound LDAP traffic should not be allowed outbound through your perimeter firewall. This search will help determine if you have any LDAP connections to IP addresses outside of private (RFC1918) address space.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-02-17
- **Author**: Jose Hernandez, Michael Haag, Splunk
- **ID**: 4d16a90c-d1a9-4d17-8156-d0db0c73c449


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), dest_port=map_get(input_event, "dest_port"), event_id=ucast(map_get(input_event, "event_id"), "string", null), dest_ip=ucast(map_get(input_event, "dest_device_ips"), "collection<string>", [])[0] 
| where dest_port=389 OR dest_port=1389 OR dest_port=636 
| where NOT (cidrmatch(ip: dest_ip, cidr_range: "10.0.0.0/8") OR cidrmatch(ip: dest_ip, cidr_range: "192.168.0.0/16") OR cidrmatch(ip: dest_ip, cidr_range: "172.16.0.0/12")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)), body=create_map(["event_id", event_id, "dest_port", dest_port, "dest_ip", dest_ip]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `tcp_command_and_scripting_interpreter_outbound_ldap_traffic_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest_device_id
* process_name
* parent_process_name
* process_path
* dest_user_id
* process
* cmd_line


#### How To Implement
To successfully implement this search you need to be ingesting information on network traffic, specifically data that populates the Network_Traffic datamodel. To develop this analytic we used specifically Zeek/Bro conn.log and PAN Traffic events.

#### Known False Positives
Unknown at this moment. Outbound LDAP traffic should not be allowed outbound through your perimeter firewall. Please check those servers to verify if the activity is legitimate.

#### Associated Analytic story
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)


#### Kill Chain Phase
* Execution



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | An outbound LDAP connection from $src_ip$ in your infrastructure connecting to dest ip $dest_ip$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/](https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/)
* [https://www.splunk.com/en_us/blog/security/simulating-detecting-and-responding-to-log4shell-with-splunk.html](https://www.splunk.com/en_us/blog/security/simulating-detecting-and-responding-to-log4shell-with-splunk.html)
* [https://www.cisa.gov/uscert/ncas/alerts/aa21-356a](https://www.cisa.gov/uscert/ncas/alerts/aa21-356a)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/log4shell_ldap_traffic/pantraffic.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/log4shell_ldap_traffic/pantraffic.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/network/tcp_command_and_scripting_interpreter_outbound_ldap_traffic.yml) \| *version*: **1**