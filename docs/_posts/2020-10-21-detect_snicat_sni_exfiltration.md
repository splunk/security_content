---
title: "Detect SNICat SNI Exfiltration"
excerpt: "Exfiltration Over C2 Channel
"
categories:
  - Network
last_modified_at: 2020-10-21
toc: true
toc_label: ""
tags:
  - Exfiltration Over C2 Channel
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for commands that the SNICat tool uses in the TLS SNI field.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-10-21
- **Author**: Shannon Davis, Splunk
- **ID**: 82d06410-134c-11eb-adc1-0242ac120002


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Exfiltration |

#### Search

```
`zeek_ssl` 
| rex field=server_name "(?<snicat>(LIST
|LS
|SIZE
|LD
|CB
|CD
|EX
|ALIVE
|EXIT
|WHERE
|finito)-[A-Za-z0-9]{16}\.)" 
| stats count by src_ip dest_ip server_name snicat 
| where count>0 
| table src_ip dest_ip server_name snicat 
| `detect_snicat_sni_exfiltration_filter`
```

#### Macros
The SPL above uses the following Macros:
* [zeek_ssl](https://github.com/splunk/security_content/blob/develop/macros/zeek_ssl.yml)

Note that `detect_snicat_sni_exfiltration_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* server_name
* src_ip
* dest_ip


#### How To Implement
You must be ingesting Zeek SSL data into Splunk. Zeek data should also be getting ingested in JSON format.  We are detecting when any of the predefined SNICat commands are found within the server_name (SNI) field. These commands are LIST, LS, SIZE, LD, CB, EX, ALIVE, EXIT, WHERE, and finito.  You can go further once this has been detected, and run other searches to decode the SNI data to prove or disprove if any data exfiltration has taken place.

#### Known False Positives
Unknown

#### Associated Analytic story
* [Data Exfiltration](/stories/data_exfiltration)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference

* [https://www.mnemonic.no/blog/introducing-snicat/](https://www.mnemonic.no/blog/introducing-snicat/)
* [https://github.com/mnemonic-no/SNIcat](https://github.com/mnemonic-no/SNIcat)
* [https://attack.mitre.org/techniques/T1041/](https://attack.mitre.org/techniques/T1041/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_snicat_sni_exfiltration.yml) \| *version*: **1**