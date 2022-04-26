---
title: "SQL Injection with Long URLs"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Web
last_modified_at: 2020-07-21
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

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for long URLs that have several SQL commands visible within them.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)

- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: e0aad4cf-0790-423b-8328-7564d0d938f9


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Web where Web.dest_category=web_server AND (Web.url_length > 1024 OR Web.http_user_agent_length > 200) by Web.src Web.dest Web.url Web.url_length Web.http_user_agent 
| `drop_dm_object_name("Web")` 
| eval num_sql_cmds=mvcount(split(url, "alter%20table")) + mvcount(split(url, "between")) + mvcount(split(url, "create%20table")) + mvcount(split(url, "create%20database")) + mvcount(split(url, "create%20index")) + mvcount(split(url, "create%20view")) + mvcount(split(url, "delete")) + mvcount(split(url, "drop%20database")) + mvcount(split(url, "drop%20index")) + mvcount(split(url, "drop%20table")) + mvcount(split(url, "exists")) + mvcount(split(url, "exec")) + mvcount(split(url, "group%20by")) + mvcount(split(url, "having")) + mvcount(split(url, "insert%20into")) + mvcount(split(url, "inner%20join")) + mvcount(split(url, "left%20join")) + mvcount(split(url, "right%20join")) + mvcount(split(url, "full%20join")) + mvcount(split(url, "select")) + mvcount(split(url, "distinct")) + mvcount(split(url, "select%20top")) + mvcount(split(url, "union")) + mvcount(split(url, "xp_cmdshell")) - 24 
| where num_sql_cmds > 3 
| `sql_injection_with_long_urls_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `sql_injection_with_long_urls_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### Kill Chain Phase
* Delivery



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/web/sql_injection_with_long_urls.yml) \| *version*: **2**