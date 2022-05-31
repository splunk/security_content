---
title: "Web Spring4Shell HTTP Request Class Module"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Web
last_modified_at: 2022-04-06
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-22965
  - Web
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the payload related to Spring4Shell, CVE-2022-22965. This analytic uses Splunk Stream HTTP to view the http request body, form data. STRT reviewed all the current proof of concept code and determined the commonality with the payloads being passed used the same fields "class.module.classLoader.resources.context.parent.pipeline.first".

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2022-04-06
- **Author**: Michael Haag, Splunk
- **ID**: fcdfd69d-0ca3-4476-920e-9b633cb4593e


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
| [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) | A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it. | 7.5 |



</div>
</details>

#### Search 

```
`stream_http` http_method IN ("POST") 
| stats values(form_data) as http_request_body min(_time) as firstTime max(_time) as lastTime count by http_method http_user_agent uri_path url bytes_in bytes_out 
| search http_request_body IN ("*class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_*", "*class.module.classLoader.resources.context.parent.pipeline.first.pattern*","*suffix=.jsp*") 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `web_spring4shell_http_request_class_module_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [stream_http](https://github.com/splunk/security_content/blob/develop/macros/stream_http.yml)

> :information_source:
> **web_spring4shell_http_request_class_module_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* http_request_body
* http_method
* http_user_agent
* uri_path
* url
* bytes_in
* bytes_out


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the stream HTTP logs or network logs that catch network traffic. Make sure that the http-request-body, payload, or request field is enabled.

#### Known False Positives
False positives may occur and filtering may be required. Restrict analytic to asset type.

#### Associated Analytic story
* [Spring4Shell CVE-2022-22965](/stories/spring4shell_cve-2022-22965)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | A http body request related to Spring4Shell has been sent to $dest$ by $src$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://github.com/DDuarte/springshell-rce-poc/blob/master/poc.py](https://github.com/DDuarte/springshell-rce-poc/blob/master/poc.py)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/http_request_body_streams.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/http_request_body_streams.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/web/web_spring4shell_http_request_class_module.yml) \| *version*: **1**