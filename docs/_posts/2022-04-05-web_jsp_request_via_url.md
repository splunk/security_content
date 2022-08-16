---
title: "Web JSP Request via URL"
excerpt: "Web Shell
, Server Software Component
, Exploit Public-Facing Application
"
categories:
  - Web
last_modified_at: 2022-04-05
toc: true
toc_label: ""
tags:
  - Web Shell
  - Server Software Component
  - Exploit Public-Facing Application
  - Persistence
  - Persistence
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-22965
  - Web
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the common URL requests used by a recent CVE - CVE-2022-22965, or Spring4Shell, to access a webshell on the remote webserver. The filename and cmd are arbitrary in this exploitation. Java will write a JSP to disk and a process will spawn from Java based on the cmd passed. This is indicative of typical web shell activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)- **Datasource**: [Splunk Add-on for NGINX](https://splunkbase.splunk.com/app/3258)
- **Last Updated**: 2022-04-05
- **Author**: Michael Haag, Splunk
- **ID**: 2850c734-2d44-4431-8139-1a56f6f54c01


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | Persistence |

| [T1505](https://attack.mitre.org/techniques/T1505/) | Server Software Component | Persistence |

| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) | A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it. | 7.5 |



</div>
</details>

#### Search 

```

| tstats count from datamodel=Web where Web.http_method IN ("GET") Web.url IN ("*.jsp?cmd=*","*j&cmd=*") by Web.http_user_agent Web.http_method, Web.url,Web.url_length Web.src, Web.dest sourcetype 
| `drop_dm_object_name("Web")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `web_jsp_request_via_url_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **web_jsp_request_via_url_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Web.http_method
* Web.url
* Web.url_length
* Web.src
* Web.dest
* Web.http_user_agent


#### How To Implement
To successfully implement this search you need to be ingesting information on Web traffic that include fields relavent for traffic into the `Web` datamodel.

#### Known False Positives
False positives may be present with legitimate applications. Attempt to filter by dest IP or use Asset groups to restrict to servers.

#### Associated Analytic story
* [Spring4Shell CVE-2022-22965](/stories/spring4shell_cve-2022-22965)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | A suspicious URL has been requested against $dest$ by $src$, related to web shell activity. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.microsoft.com/security/blog/2022/04/04/springshell-rce-vulnerability-guidance-for-protecting-against-and-detecting-cve-2022-22965/](https://www.microsoft.com/security/blog/2022/04/04/springshell-rce-vulnerability-guidance-for-protecting-against-and-detecting-cve-2022-22965/)
* [https://github.com/TheGejr/SpringShell](https://github.com/TheGejr/SpringShell)
* [https://www.tenable.com/blog/spring4shell-faq-spring-framework-remote-code-execution-vulnerability](https://www.tenable.com/blog/spring4shell-faq-spring-framework-remote-code-execution-vulnerability)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/spring4shell_nginx.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/spring4shell_nginx.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/web/web_jsp_request_via_url.yml) \| *version*: **1**