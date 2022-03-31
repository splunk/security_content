---
title: "Detect Long DNS TXT Record Response"
excerpt: "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is used to detect attempts to use DNS tunneling, by calculating the length of responses to DNS TXT queries. Endpoints using DNS as a method of transmission for data exfiltration, command and control, or evasion of security controls can often be detected by noting unusually large volumes of DNS traffic. Deprecated because this detection should focus on DNS queries instead of DNS responses.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk
- **ID**: 05437c07-62f5-452e-afdc-04dd44815bb9


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Command & Control


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.message_type=response AND DNS.record_type=TXT by DNS.src DNS.dest DNS.answer DNS.record_type 
|  `drop_dm_object_name("DNS")` 
| eval anslen=len(answer) 
| search anslen>100 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| rename src as "Source IP", dest as "Destination IP", answer as "DNS Answer" anslen as "Answer Length" record_type as "DNS Record Type" firstTime as "First Time" lastTime as "Last Time" count as Count 
| table "Source IP" "Destination IP" "DNS Answer" "DNS Record Type"  "Answer Length" Count "First Time" "Last Time" 
| `detect_long_dns_txt_record_response_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_long_dns_txt_record_response_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.message_type
* DNS.record_type
* DNS.src
* DNS.dest
* DNS.answer


#### How To Implement
To successfully implement this search you need to ingest data from your DNS logs, or monitor DNS traffic using Stream, Bro or something similar. Specifically, this query requires that the DNS data model is populated with information regarding the DNS record type that is being returned as well as the data in the answer section of the protocol.

#### Known False Positives
It's possible that legitimate TXT record responses can be long enough to trigger this search. You can modify the packet threshold for this search to help mitigate false positives.

#### Associated Analytic story
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Command and Control](/stories/command_and_control)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_long_dns_txt_record_response.yml) \| *version*: **2**