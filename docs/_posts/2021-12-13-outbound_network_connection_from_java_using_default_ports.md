---
title: "Outbound Network Connection from Java Using Default Ports"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Endpoint
last_modified_at: 2021-12-13
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-44228
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

A required step while exploiting the CVE-2021-44228-Log4j vulnerability is that the victim server will perform outbound connections to attacker-controlled infrastructure. This is required as part of the JNDI lookup as well as for retrieving the second stage .class payload. The following analytic identifies the Java process reaching out to default ports used by the LDAP and RMI protocols. This behavior could represent successfull exploitation. Note that adversaries can easily decide to use arbitrary ports for these protocols and potentially bypass this detection.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-12-13
- **Author**: Mauricio Velazco, Splunk
- **ID**: d2c14d28-5c47-11ec-9892-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where (Processes.process_name="java.exe" OR Processes.process_name=javaw.exe OR Processes.process_name=javaw.exe) by _time Processes.process_guid Processes.process_name Processes.dest Processes.process_path Processes.process Processes.parent_process_name 
|  `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| join  process_guid [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Ports where (Ports.dest_port= 389 OR Ports.dest_port= 636 OR Ports.dest_port = 1389 OR Ports.dest_port = 1099 ) by Ports.process_guid Ports.dest Ports.dest_port
| `drop_dm_object_name(Ports)` 
|  rename  dest as connection_to_CNC] 
| table _time dest parent_process_name process_name process_path process connection_to_CNC dest_port 
| `outbound_network_connection_from_java_using_default_ports_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `outbound_network_connection_from_java_using_default_ports_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_guid
* Processes.process_name
* Processes.dest
* Processes.process_path
* Processes.process
* Processes.parent_process_name
* Ports.process_guid
* Ports.dest
* Ports.dest_port


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Legitimate Java applications may use perform outbound connections to these ports. Filter as needed

#### Associated Analytic story
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 90 | 60 | Java performed outbound connections to default ports of LDAP or RMI on $dest$ |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects. | 9.3 |



#### Reference

* [https://www.lunasec.io/docs/blog/log4j-zero-day/](https://www.lunasec.io/docs/blog/log4j-zero-day/)
* [https://www.govcert.admin.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/](https://www.govcert.admin.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/outbound_java/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/outbound_java/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/outbound_network_connection_from_java_using_default_ports.yml) \| *version*: **1**