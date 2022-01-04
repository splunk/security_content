---
title: "Java Class File download by Java User Agent"
excerpt: "Exploit Public-Facing Application"
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
  - Web
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a Java user agent performing a GET request for a .class file from the remote site. This is potentially indicative of exploitation of the Java application and may be related to current event CVE-2021-44228 (Log4Shell).

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2021-12-13
- **Author**: Michael Haag, Splunk
- **ID**: 8281ce42-5c50-11ec-82d2-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

#### Search

```

| tstats count from datamodel=Web where Web.http_user_agent="*Java*" Web.http_method="GET" Web.url="*.class*" by Web.http_user_agent Web.http_method, Web.url,Web.url_length Web.src, Web.dest 
| `drop_dm_object_name("Web")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `java_class_file_download_by_java_user_agent_filter`
```

#### Associated Analytic Story
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)


#### How To Implement
To successfully implement this search, you need to be ingesting web or proxy logs, or ensure it is being filled by a proxy like device, into the Web Datamodel. For additional filtering, allow list private IP space or restrict by known good.

#### Required field
* _time
* Web.http_method
* Web.url
* Web.url_length
* Web.src
* Web.dest
* Web.http_user_agent


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Filtering may be required in some instances, filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 80 | 50 | A Java user agent $http_user_agent$ was performing a $http_method$ to retrieve a remote class file. |



#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects. | 9.3 |



#### Reference

* [https://arstechnica.com/information-technology/2021/12/as-log4shell-wreaks-havoc-payroll-service-reports-ransomware-attack/](https://arstechnica.com/information-technology/2021/12/as-log4shell-wreaks-havoc-payroll-service-reports-ransomware-attack/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/java/java.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/java/java.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/java_class_file_download_by_java_user_agent.yml) \| *version*: **1**