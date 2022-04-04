---
title: "Monitor DNS For Brand Abuse"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2017-09-23
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for DNS requests for faux domains similar to the domains that you want to have monitored for abuse.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2017-09-23
- **Author**: David Dorsey, Splunk
- **ID**: 24dd17b1-e2fb-4c31-878c-d4f746595bfa


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Delivery
* Actions on Objectives


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

| tstats `security_content_summariesonly` values(DNS.answer) as IPs min(_time) as firstTime from datamodel=Network_Resolution by DNS.src, DNS.query 
| `drop_dm_object_name("DNS")` 
| `security_content_ctime(firstTime)`
| `brand_abuse_dns` 
| `monitor_dns_for_brand_abuse_filter`
```

#### Macros
The SPL above uses the following Macros:
* [brand_abuse_dns](https://github.com/splunk/security_content/blob/develop/macros/brand_abuse_dns.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **monitor_dns_for_brand_abuse_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You need to ingest data from your DNS logs. Specifically you must ingest the domain that is being queried and the IP of the host originating the request. Ideally, you should also be ingesting the answer to the query and the query type. This approach allows you to also create your own localized passive DNS capability which can aid you in future investigations. You also need to have run the search "ESCU - DNSTwist Domain Names", which creates the permutations of the domain that will be checked for.

#### Known False Positives
None at this time

#### Associated Analytic story
* [Brand Monitoring](/stories/brand_monitoring)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/monitor_dns_for_brand_abuse.yml) \| *version*: **1**