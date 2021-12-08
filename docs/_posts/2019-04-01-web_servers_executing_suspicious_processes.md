---
title: "Web Servers Executing Suspicious Processes"
excerpt: "System Information Discovery"
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

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for suspicious processes on all systems labeled as web servers.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2019-04-01
- **Author**: David Dorsey, Splunk
- **ID**: ec3b7601-689a-4463-94e0-c9f45638efb9


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.dest_category="web_server" AND (Processes.process="*whoami*" OR Processes.process="*ping*" OR Processes.process="*iptables*" OR Processes.process="*wget*" OR Processes.process="*service*" OR Processes.process="*curl*") by Processes.process Processes.process_name, Processes.dest Processes.user
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `web_servers_executing_suspicious_processes_filter`
```

#### Associated Analytic Story
* [Apache Struts Vulnerability](/stories/apache_struts_vulnerability)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model. In addition, web servers will need to be identified in the Assets and Identity Framework of Enterprise Security.

#### Required field
* _time
* Processes.dest_category
* Processes.process
* Processes.process_name
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Some of these processes may be used legitimately on web servers during maintenance or other administrative tasks.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/web_servers_executing_suspicious_processes.yml) \| *version*: **1**