---
title: "Exchange PowerShell Abuse via SSRF"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Endpoint
last_modified_at: 2021-08-27
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies suspicious behavior related to ProxyShell against on-premise Microsoft Exchange servers. \
Modification of this analytic is requried to ensure fields are mapped accordingly. \
A suspicious event will have `PowerShell`, the method `POST` and `autodiscover.json`. This is indicative of accessing PowerShell on the back end of Exchange with SSRF. \
An event will look similar to `POST /autodiscover/autodiscover.json a=dsxvu@fnsso.flq/powershell/?X-Rps-CAT=VgEAVAdXaW5kb3d...` (abbreviated) \
Review the source attempting to perform this activity against your environment. In addition, review PowerShell logs and access recently granted to Exchange roles.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-08-27
- **Author**: Michael Haag, Splunk
- **ID**: 29228ab4-0762-11ec-94aa-acde48001122


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

| `exchange` c_uri="*//autodiscover.json*" cs_uri_query="*PowerShell*" cs_method="POST" 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, cs_uri_query, cs_method, c_uri 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `exchange_powershell_abuse_via_ssrf_filter`
```

#### Macros
The SPL above uses the following Macros:
* [exchange](https://github.com/splunk/security_content/blob/develop/macros/exchange.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **exchange_powershell_abuse_via_ssrf_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* cs_uri_query
* cs_method
* c_uri


#### How To Implement
The following analytic requires on-premise Exchange to be logging to Splunk using the TA - https://splunkbase.splunk.com/app/3225. Ensure logs are parsed correctly, or tune the analytic for your environment.

#### Known False Positives
Limited false positives, however, tune as needed.

#### Associated Analytic story
* [ProxyShell](/stories/proxyshell)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | Activity related to ProxyShell has been identified on $dest$. Review events and take action accordingly. |


#### Reference

* [https://github.com/GossiTheDog/ThreatHunting/blob/master/AzureSentinel/Exchange-Powershell-via-SSRF](https://github.com/GossiTheDog/ThreatHunting/blob/master/AzureSentinel/Exchange-Powershell-via-SSRF)
* [https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html](https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html)
* [https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1](https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/exchange-events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/exchange-events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/exchange_powershell_abuse_via_ssrf.yml) \| *version*: **1**