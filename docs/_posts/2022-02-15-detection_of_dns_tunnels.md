---
title: "Detection of DNS Tunnels"
excerpt: "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
"
categories:
  - Deprecated
last_modified_at: 2022-02-15
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

This search is used to detect DNS tunneling, by calculating the sum of the length of DNS queries and DNS answers. The search also filters out potential false positives by filtering out queries made to internal systems and the queries originating from internal DNS, Web, and Email servers. Endpoints using DNS as a method of transmission for data exfiltration, command and control, or evasion of security controls can often be detected by noting an unusually large volume of DNS traffic. \
NOTE:Deprecated because existing detection is doing the same. This detection is replaced with two other variations, if you are using MLTK then you can use this search `ESCU - DNS Query Length Outliers - MLTK - Rule` or use the standard deviation version `ESCU - DNS Query Length With High Standard Deviation - Rule`, as an alternantive.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)

- **Last Updated**: 2022-02-15
- **Author**: Bhavin Patel, Splunk
- **ID**: 104658f4-afdc-499f-9719-17a43f9826f4


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |

#### Search

```

| tstats `security_content_summariesonly` dc("DNS.query") as count  from datamodel=Network_Resolution  where nodename=DNS "DNS.message_type"="QUERY" NOT (`cim_corporate_web_domain_search("DNS.query")`) NOT "DNS.query"="*.in-addr.arpa" NOT ("DNS.src_category"="svc_infra_dns" OR "DNS.src_category"="svc_infra_webproxy" OR "DNS.src_category"="svc_infra_email*"   ) by "DNS.src","DNS.query" 
| rename "DNS.src" as src  "DNS.query" as message 
| eval length=len(message) 
| stats sum(length) as length by src 
| append [ tstats `security_content_summariesonly` dc("DNS.answer") as count  from datamodel=Network_Resolution  where nodename=DNS "DNS.message_type"="QUERY" NOT (`cim_corporate_web_domain_search("DNS.query")`) NOT "DNS.query"="*.in-addr.arpa" NOT ("DNS.src_category"="svc_infra_dns" OR "DNS.src_category"="svc_infra_webproxy" OR "DNS.src_category"="svc_infra_email*"   ) by "DNS.src","DNS.answer" 
| rename "DNS.src" as src  "DNS.answer" as message 
| eval message=if(message=="unknown","", message) 
| eval length=len(message) 
| stats sum(length) as length by src ] 
| stats sum(length) as length by src 
| where length > 10000 
| `detection_of_dns_tunnels_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detection_of_dns_tunnels_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.query
* DNS.message_type
* DNS.src_category
* DNS.src


#### How To Implement
To successfully implement this search, we must ensure that DNS data is being ingested and mapped to the appropriate fields in the Network_Resolution data model. Fields like src_category are automatically provided by the Assets and Identity Framework shipped with Splunk Enterprise Security. You will need to ensure you are using the Assets and Identity Framework and populating the src_category field. You will also need to enable the `cim_corporate_web_domain_search()` macro which will essentially filter out the DNS queries made to the corporate web domains to reduce alert fatigue.

#### Known False Positives
It's possible that normal DNS traffic will exhibit this behavior. If an alert is generated, please investigate and validate as appropriate. The threshold can also be modified to better suit your environment.

#### Associated Analytic story
* [Data Protection](/stories/data_protection)
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Command and Control](/stories/command_and_control)


#### Kill Chain Phase
* Command & Control
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detection_of_dns_tunnels.yml) \| *version*: **2**