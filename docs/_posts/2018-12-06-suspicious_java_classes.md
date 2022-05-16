---
title: "Suspicious Java Classes"
excerpt: ""
categories:
  - Application
last_modified_at: 2018-12-06
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for suspicious Java classes that are often used to exploit remote command execution in common Java frameworks, such as Apache Struts.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2018-12-06
- **Author**: Jose Hernandez, Splunk
- **ID**: 6ed33786-5e87-4f55-b62c-cb5f1168b831


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

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

* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 7
* CIS 12



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`stream_http` http_method=POST http_content_length>1 
| regex form_data="(?i)java\.lang\.(?:runtime
|processbuilder)" 
| rename src_ip as src 
| stats count earliest(_time) as firstTime, latest(_time) as lastTime, values(url) as uri, values(status) as status, values(http_user_agent) as http_user_agent by src, dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_java_classes_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [stream_http](https://github.com/splunk/security_content/blob/develop/macros/stream_http.yml)

Note that **suspicious_java_classes_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* http_method
* http_content_length
* src_ip
* url
* status
* http_user_agent
* src
* dest


#### How To Implement
In order to properly run this search, Splunk needs to ingest data from your web-traffic appliances that serve or sit in the path of your Struts application servers. This can be accomplished by indexing data from a web proxy, or by using network traffic-analysis tools, such as Splunk Stream or Bro.

#### Known False Positives
There are no known false positives.

#### Associated Analytic story
* [Apache Struts Vulnerability](/stories/apache_struts_vulnerability)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/suspicious_java_classes.yml) \| *version*: **1**