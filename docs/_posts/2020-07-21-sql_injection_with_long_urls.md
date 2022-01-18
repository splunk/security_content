---
title: "SQL Injection with Long URLs"
excerpt: "Exploit Public-Facing Application"
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

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for long URLs that have several SQL commands visible within them.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: e0aad4cf-0790-423b-8328-7564d0d938f9


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Web where Web.dest_category=web_server AND (Web.url_length > 1024 OR Web.http_user_agent_length > 200) by Web.src Web.dest Web.url Web.url_length Web.http_user_agent 
| `drop_dm_object_name("Web")` 
| eval num_sql_cmds=mvcount(split(url, "alter%20table")) + mvcount(split(url, "between")) + mvcount(split(url, "create%20table")) + mvcount(split(url, "create%20database")) + mvcount(split(url, "create%20index")) + mvcount(split(url, "create%20view")) + mvcount(split(url, "delete")) + mvcount(split(url, "drop%20database")) + mvcount(split(url, "drop%20index")) + mvcount(split(url, "drop%20table")) + mvcount(split(url, "exists")) + mvcount(split(url, "exec")) + mvcount(split(url, "group%20by")) + mvcount(split(url, "having")) + mvcount(split(url, "insert%20into")) + mvcount(split(url, "inner%20join")) + mvcount(split(url, "left%20join")) + mvcount(split(url, "right%20join")) + mvcount(split(url, "full%20join")) + mvcount(split(url, "select")) + mvcount(split(url, "distinct")) + mvcount(split(url, "select%20top")) + mvcount(split(url, "union")) + mvcount(split(url, "xp_cmdshell")) - 24 
| where num_sql_cmds > 3 
| `sql_injection_with_long_urls_filter`
```

#### Associated Analytic Story
* [SQL Injection](/stories/sql_injection)


#### How To Implement
To successfully implement this search, you need to be monitoring network communications to your web servers or ingesting your HTTP logs and populating the Web data model. You must also identify your web servers in the Enterprise Security assets table.

#### Required field
* _time
* Web.dest_category
* Web.url_length
* Web.http_user_agent_length
* Web.src
* Web.dest
* Web.url
* Web.http_user_agent


#### Kill Chain Phase
* Delivery


#### Known False Positives
It&#39;s possible that legitimate traffic will have long URLs or long user agent strings and that common SQL commands may be found within the URL. Please investigate as appropriate.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/web/sql_injection_with_long_urls.yml) \| *version*: **2**