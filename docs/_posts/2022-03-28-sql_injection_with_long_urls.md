---
title: "SQL Injection with Long URLs"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Web
last_modified_at: 2022-03-28
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

### :warning: WARNING THIS IS A EXPERIMENTAL analytic
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for long URLs that have several SQL commands visible within them.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2022-03-28
- **Author**: Bhavin Patel, Splunk
- **ID**: e0aad4cf-0790-423b-8328-7564d0d938f9


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Delivery


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.DS
* ID.RA
* PR.PT
* PR.IP
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 4
* CIS 13
* CIS 18



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count from datamodel=Web where Web.dest_category=web_server AND (Web.url_length > 1024 OR Web.http_user_agent_length > 200) by Web.src Web.dest Web.url Web.url_length Web.http_user_agent 
| `drop_dm_object_name("Web")` 
| eval url=lower(url) 
| eval num_sql_cmds=mvcount(split(url, "alter%20table")) + mvcount(split(url, "between")) + mvcount(split(url, "create%20table")) + mvcount(split(url, "create%20database")) + mvcount(split(url, "create%20index")) + mvcount(split(url, "create%20view")) + mvcount(split(url, "delete")) + mvcount(split(url, "drop%20database")) + mvcount(split(url, "drop%20index")) + mvcount(split(url, "drop%20table")) + mvcount(split(url, "exists")) + mvcount(split(url, "exec")) + mvcount(split(url, "group%20by")) + mvcount(split(url, "having")) + mvcount(split(url, "insert%20into")) + mvcount(split(url, "inner%20join")) + mvcount(split(url, "left%20join")) + mvcount(split(url, "right%20join")) + mvcount(split(url, "full%20join")) + mvcount(split(url, "select")) + mvcount(split(url, "distinct")) + mvcount(split(url, "select%20top")) + mvcount(split(url, "union")) + mvcount(split(url, "xp_cmdshell")) - 24 
| where num_sql_cmds > 3 
| `sql_injection_with_long_urls_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **sql_injection_with_long_urls_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Web.dest_category
* Web.url_length
* Web.http_user_agent_length
* Web.src
* Web.dest
* Web.url
* Web.http_user_agent


#### How To Implement
To successfully implement this search, you need to be monitoring network communications to your web servers or ingesting your HTTP logs and populating the Web data model. You must also identify your web servers in the Enterprise Security assets table.

#### Known False Positives
It's possible that legitimate traffic will have long URLs or long user agent strings and that common SQL commands may be found within the URL. Please investigate as appropriate.

#### Associated Analytic story
* [SQL Injection](/stories/sql_injection)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | SQL injection attempt with url $url$ detected on $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/web/sql_injection_with_long_urls.yml) \| *version*: **3**