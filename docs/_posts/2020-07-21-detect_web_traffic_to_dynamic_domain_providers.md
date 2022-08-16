---
title: "Detect web traffic to dynamic domain providers"
excerpt: "Web Protocols
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Web Protocols
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for web connections to dynamic DNS providers.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 134da869-e264-4a8f-8d7e-fcd01c18f301


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | Command And Control |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Command & Control
* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.IP
* DE.DP



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 7
* CIS 8



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count values(Web.url) as url min(_time) as firstTime from datamodel=Web where Web.status=200 by Web.src Web.dest Web.status 
| `drop_dm_object_name("Web")` 
| `security_content_ctime(firstTime)` 
| `dynamic_dns_web_traffic` 
| `detect_web_traffic_to_dynamic_domain_providers_filter`
```

#### Macros
The SPL above uses the following Macros:
* [dynamic_dns_web_traffic](https://github.com/splunk/security_content/blob/develop/macros/dynamic_dns_web_traffic.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **detect_web_traffic_to_dynamic_domain_providers_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Web.url
* Web.status
* Web.src
* Web.dest


#### How To Implement
This search requires you to be ingesting web-traffic logs. You can obtain these logs from indexing data from a web proxy or by using a network-traffic-analysis tool, such as Bro or Splunk Stream. The web data model must contain the URL being requested, the IP address of the host initiating the request, and the destination IP. This search also leverages a lookup file, `dynamic_dns_providers_default.csv`, which contains a non-exhaustive list of dynamic DNS providers. Consider periodically updating this local lookup file with new domains.\
This search produces fields (`isDynDNS`) that are not yet supported by ES Incident Review and therefore cannot be viewed when a notable event is raised. These fields contribute additional context to the notable. To see the additional metadata, add the following fields, if not already present, to Incident Review - Event Attributes (Configure > Incident Management > Incident Review Settings > Add New Entry):\\n1. **Label:** IsDynamicDNS, **Field:** isDynDNS\
Detailed documentation on how to create a new field within Incident Review may be found here: `https://docs.splunk.com/Documentation/ES/5.3.0/Admin/Customizenotables#Add_a_field_to_the_notable_event_details` Deprecated because duplicate.

#### Known False Positives
It is possible that list of dynamic DNS providers is outdated and/or that the URL being requested is legitimate.

#### Associated Analytic story
* [Dynamic DNS](/stories/dynamic_dns)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_web_traffic_to_dynamic_domain_providers.yml) \| *version*: **2**