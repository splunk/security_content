---
title: "Detect hosts connecting to dynamic domain providers"
excerpt: "Drive-by Compromise
"
categories:
  - Network
last_modified_at: 2021-01-14
toc: true
toc_label: ""
tags:
  - Drive-by Compromise
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Malicious actors often abuse legitimate Dynamic DNS services to host malicious payloads or interactive command and control nodes. Attackers will automate domain resolution changes by routing dynamic domains to countless IP addresses to circumvent firewall blocks, block lists as well as frustrate a network defenders analytic and investigative processes. This search will look for DNS queries made from within your infrastructure to suspicious dynamic domains.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2021-01-14
- **Author**: Bhavin Patel, Splunk
- **ID**: a1e761ac-1344-4dbd-88b2-3f34c912d359


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1189](https://attack.mitre.org/techniques/T1189/) | Drive-by Compromise | Initial Access |

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

* PR.DS
* PR.PT
* DE.AE
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 8
* CIS 12
* CIS 13



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count values(DNS.answer) as answer min(_time) as firstTime from datamodel=Network_Resolution by DNS.query host 
| `drop_dm_object_name("DNS")` 
| `security_content_ctime(firstTime)` 
| `dynamic_dns_providers` 
| `detect_hosts_connecting_to_dynamic_domain_providers_filter`
```

#### Macros
The SPL above uses the following Macros:
* [dynamic_dns_providers](https://github.com/splunk/security_content/blob/develop/macros/dynamic_dns_providers.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_hosts_connecting_to_dynamic_domain_providers_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.answer
* DNS.query
* host


#### How To Implement
First, you'll need to ingest data from your DNS operations. This can be done by ingesting logs from your server or data, collected passively by Splunk Stream or a similar solution. Specifically, data that contains the domain that is being queried and the IP of the host originating the request must be populating the `Network_Resolution` data model. This search also leverages a lookup file, `dynamic_dns_providers_default.csv`, which contains a non-exhaustive list of Dynamic DNS providers. Please consider updating the local lookup periodically by adding new domains to the list of `dynamic_dns_providers_local.csv`.\
This search produces fields (query, answer, isDynDNS) that are not yet supported by ES Incident Review and therefore cannot be viewed when a notable event is raised. These fields contribute additional context to the notable event. To see the additional metadata, add the following fields, if not already present, to Incident Review. Event Attributes (Configure > Incident Management > Incident Review Settings > Add New Entry):\\n1. **Label:** DNS Query, **Field:** query\
1. \
1. **Label:** DNS Answer, **Field:** answer\
1. \
1. **Label:** IsDynamicDNS, **Field:** isDynDNS\
Detailed documentation on how to create a new field within Incident Review may be found here: `https://docs.splunk.com/Documentation/ES/5.3.0/Admin/Customizenotables#Add_a_field_to_the_notable_event_details`

#### Known False Positives
Some users and applications may leverage Dynamic DNS to reach out to some domains on the Internet since dynamic DNS by itself is not malicious, however this activity must be verified.

#### Associated Analytic story
* [Data Protection](/stories/data_protection)
* [Prohibited Traffic Allowed or Protocol Mismatch](/stories/prohibited_traffic_allowed_or_protocol_mismatch)
* [DNS Hijacking](/stories/dns_hijacking)
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Dynamic DNS](/stories/dynamic_dns)
* [Command and Control](/stories/command_and_control)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A dns query $query$ from your infra connecting to suspicious domain in host  $host$ |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1189/dyn_dns_site/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1189/dyn_dns_site/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/network/detect_hosts_connecting_to_dynamic_domain_providers.yml) \| *version*: **3**