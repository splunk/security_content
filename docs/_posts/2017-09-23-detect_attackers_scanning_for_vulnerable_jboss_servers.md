---
title: "Detect attackers scanning for vulnerable JBoss servers"
excerpt: "System Information Discovery"
categories:
  - Web
last_modified_at: 2017-09-23
toc: true
toc_label: ""
tags:
  - System Information Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for specific GET or HEAD requests to web servers that are indicative of reconnaissance attempts to identify vulnerable JBoss servers. JexBoss is described as the exploit tool of choice for this malicious activity.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2017-09-23
- **Author**: Bhavin Patel, Splunk
- **ID**: 104658f4-afdc-499e-9719-17243f982681


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.http_method="GET" OR Web.http_method="HEAD") AND (Web.url="*/web-console/ServerInfo.jsp*" OR Web.url="*web-console*" OR Web.url="*jmx-console*" OR Web.url = "*invoker*") by Web.http_method, Web.url, Web.src, Web.dest 
| `drop_dm_object_name("Web")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_attackers_scanning_for_vulnerable_jboss_servers_filter`
```

#### Associated Analytic Story
* [JBoss Vulnerability](/stories/jboss_vulnerability)
* [SamSam Ransomware](/stories/samsam_ransomware)


#### How To Implement
You must be ingesting data from the web server or network traffic that contains web specific information, and populating the Web data model.

#### Required field
* _time
* Web.http_method
* Web.url
* Web.src
* Web.dest


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
It&#39;s possible for legitimate HTTP requests to be made to URLs containing the suspicious paths.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/web/detect_attackers_scanning_for_vulnerable_jboss_servers.yml) \| *version*: **1**