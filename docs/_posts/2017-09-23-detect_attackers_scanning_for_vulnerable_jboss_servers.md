---
title: "Detect attackers scanning for vulnerable JBoss servers"
excerpt: "System Information Discovery
"
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

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for specific GET or HEAD requests to web servers that are indicative of reconnaissance attempts to identify vulnerable JBoss servers. JexBoss is described as the exploit tool of choice for this malicious activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2017-09-23
- **Author**: Bhavin Patel, Splunk
- **ID**: 104658f4-afdc-499e-9719-17243f982681


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

* Reconnaissance


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.http_method="GET" OR Web.http_method="HEAD") AND (Web.url="*/web-console/ServerInfo.jsp*" OR Web.url="*web-console*" OR Web.url="*jmx-console*" OR Web.url = "*invoker*") by Web.http_method, Web.url, Web.src, Web.dest 
| `drop_dm_object_name("Web")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_attackers_scanning_for_vulnerable_jboss_servers_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_attackers_scanning_for_vulnerable_jboss_servers_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Web.http_method
* Web.url
* Web.src
* Web.dest


#### How To Implement
You must be ingesting data from the web server or network traffic that contains web specific information, and populating the Web data model.

#### Known False Positives
It's possible for legitimate HTTP requests to be made to URLs containing the suspicious paths.

#### Associated Analytic story
* [JBoss Vulnerability](/stories/jboss_vulnerability)
* [SamSam Ransomware](/stories/samsam_ransomware)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/web/detect_attackers_scanning_for_vulnerable_jboss_servers.yml) \| *version*: **1**