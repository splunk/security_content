---
title: "Log4Shell JNDI Payload Injection Attempt"
excerpt: "Exploit Public-Facing Application"
categories:
  - Web
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

CVE-2021-44228 Log4Shell payloads can be injected via various methods, but on of the most common vectors injection is via Web calls. Many of the vulnerable java web applications that are using log4j have a web component to them are specially targets of this injection, specifically projects like Apache Struts, Flink, Druid, and Solr. The exploit is triggered by a LDAP lookup function in the log4j package, its invocation is similar to `${jndi:ldap://PAYLOAD_INJECTED}`, when executed against vulnerable web applications the invocation can be seen in various part of web logs. Specifically it has been successfully exploited via headers like X-Forwarded-For, User-Agent, Referer, and X-Api-Version. In this detection we first limit the scope of our search to the Web Datamodel and use the `| from datamodel` function to benefit from schema accelerated searching capabilities, mainly because the second part of the detection is pretty heavy, it runs a regex across all _raw events that looks for `${jndi:ldap://` pattern across all potential web fields available to the raw data, like http headers for example. If you see results for this detection, it means that there was a attempt at a injection, which could be a reconnaissance activity or a valid expliotation attempt, but this does not exactly mean that the host was indeed successfully exploited.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2021-12-13
- **Author**: Jose Hernandez
- **ID**: c184f12e-5c90-11ec-bf1f-497c9a704a72


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

#### Search

```

| from datamodel Web.Web 
| regex _raw="[jJnNdDiI]{4}(\:
|\%3A
|\/
|\%2F)\w+(\:\/\/
|\%3A\%2F\%2F)(\$\{.*?\}(\.)?)?" 
| fillnull 
| stats count by action, category, dest, dest_port, http_content_type, http_method, http_referrer, http_user_agent, site, src, url, url_domain, user 
| `log4shell_jndi_payload_injection_attempt_filter`
```

#### Macros
The SPL above uses the following Macros:

Note that `log4shell_jndi_payload_injection_attempt_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* action
* category
* dest
* dest_port
* http_content_type
* http_method
* http_referrer
* http_user_agent
* site
* src
* url
* url_domain
* user


#### How To Implement
This detection requires the Web datamodel to be populated from a supported Technology Add-On like Splunk for Apache or Splunk for Nginx.

#### Known False Positives
If there is a vulnerablility scannner looking for log4shells this will trigger, otherwise likely to have low false positives.

#### Associated Analytic story
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)


#### Kill Chain Phase
* Reconnaissance
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 50 | 30 | CVE-2021-44228 Log4Shell triggered for host $dest$ |



#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects. | 9.3 |



#### Reference

* [https://www.lunasec.io/docs/blog/log4j-zero-day/](https://www.lunasec.io/docs/blog/log4j-zero-day/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/log4j_proxy_logs/log4j_proxy_logs.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/log4j_proxy_logs/log4j_proxy_logs.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/web/log4shell_jndi_payload_injection_attempt.yml) \| *version*: **1**