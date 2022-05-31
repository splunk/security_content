---
title: "Web Spring Cloud Function FunctionRouter"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Web
last_modified_at: 2022-04-05
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-22963
  - Web
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies activity related to the web application Spring Cloud Function that was recently idenfied as vulnerable. This is CVE-2022-22963. Multiple proof of concept code was released. The URI that is hit includes `functionrouter`. The specifics of the exploit include a status of 500. In this query we did not include it, but for filtering you can add Web.status=500. The exploit data itself (based on all the POCs) is located in the form_data field. This field will include all class.modules being called.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2022-04-05
- **Author**: Michael Haag, Splunk
- **ID**: 89dddbad-369a-4f8a-ace2-2439218735bc


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
| [CVE-2022-22963](https://nvd.nist.gov/vuln/detail/CVE-2022-22963) | In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources. | 7.5 |



</div>
</details>

#### Search 

```

| tstats count from datamodel=Web where Web.http_method IN ("POST") Web.url="*/functionRouter*" by Web.http_user_agent Web.http_method, Web.url,Web.url_length Web.src, Web.dest Web.status sourcetype 
| `drop_dm_object_name("Web")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `web_spring_cloud_function_functionrouter_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **web_spring_cloud_function_functionrouter_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
| 42.0 | 70 | 60 | A suspicious URL has been requested against $dest$ by $src$, related to a vulnerability in Spring Cloud. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://github.com/rapid7/metasploit-framework/pull/16395](https://github.com/rapid7/metasploit-framework/pull/16395)
* [https://github.com/hktalent/spring-spel-0day-poc](https://github.com/hktalent/spring-spel-0day-poc)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/all_functionrouter_http_streams.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/all_functionrouter_http_streams.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/web/web_spring_cloud_function_functionrouter.yml) \| *version*: **1**