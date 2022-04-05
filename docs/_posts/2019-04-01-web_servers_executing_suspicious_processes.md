---
title: "Web Servers Executing Suspicious Processes"
excerpt: "System Information Discovery
"
categories:
  - Application
last_modified_at: 2019-04-01
toc: true
toc_label: ""
tags:
  - System Information Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for suspicious processes on all systems labeled as web servers.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2019-04-01
- **Author**: David Dorsey, Splunk
- **ID**: ec3b7601-689a-4463-94e0-c9f45638efb9


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Discovery |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.IP



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.dest_category="web_server" AND (Processes.process="*whoami*" OR Processes.process="*ping*" OR Processes.process="*iptables*" OR Processes.process="*wget*" OR Processes.process="*service*" OR Processes.process="*curl*") by Processes.process Processes.process_name, Processes.dest Processes.user
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `web_servers_executing_suspicious_processes_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **web_servers_executing_suspicious_processes_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest_category
* Processes.process
* Processes.process_name
* Processes.dest
* Processes.user


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model. In addition, web servers will need to be identified in the Assets and Identity Framework of Enterprise Security.

#### Known False Positives
Some of these processes may be used legitimately on web servers during maintenance or other administrative tasks.

#### Associated Analytic story
* [Apache Struts Vulnerability](/stories/apache_struts_vulnerability)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/web_servers_executing_suspicious_processes.yml) \| *version*: **1**