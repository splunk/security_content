---
title: "Multiple Archive Files Http Post Traffic"
excerpt: "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
, Exfiltration Over Alternative Protocol
"
categories:
  - Network
last_modified_at: 2021-04-21
toc: true
toc_label: ""
tags:
  - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
  - Exfiltration Over Alternative Protocol
  - Exfiltration
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is designed to detect high frequency of archive files data exfiltration through HTTP POST method protocol. This are one of the common techniques used by APT or trojan spy after doing the data collection like screenshot, recording, sensitive data to the infected machines. The attacker may execute archiving command to the collected data, save it a temp folder with a hidden attribute then send it to its C2 through HTTP POST. Sometimes adversaries will rename the archive files or encode/encrypt to cover their tracks. This detection can detect a renamed archive files transfer to HTTP POST since it checks the request body header. Unfortunately this detection cannot support archive that was encrypted or encoded before doing the exfiltration.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)

- **Last Updated**: 2021-04-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 4477f3ea-a28f-11eb-b762-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |

| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Exfiltration |

#### Search

```
`stream_http` http_method=POST 
|eval archive_hdr1=substr(form_data,1,2) 
| eval archive_hdr2 = substr(form_data,1,4) 
|stats values(form_data) as http_request_body min(_time) as firstTime max(_time) as lastTime count by http_method http_user_agent uri_path url bytes_in bytes_out archive_hdr1 archive_hdr2 
|where count >20 AND (archive_hdr1 = "7z" OR archive_hdr1 = "PK" OR archive_hdr2="Rar!") 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `multiple_archive_files_http_post_traffic_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [stream_http](https://github.com/splunk/security_content/blob/develop/macros/stream_http.yml)

Note that `multiple_archive_files_http_post_traffic_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* http_method
* http_user_agent
* uri_path
* url
* bytes_in
* bytes_out
* archive_hdr1
* archive_hdr2
* form_data


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the stream HTTP logs or network logs that catch network traffic. Make sure that the http-request-body, payload, or request field is enabled in stream http configuration.

#### Known False Positives
Normal archive transfer via HTTP protocol may trip this detection.

#### Associated Analytic story
* [Data Exfiltration](/stories/data_exfiltration)
* [Command and Control](/stories/command_and_control)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | A http post $http_method$ sending packet with possible archive bytes header 4form_data$ in uri path $uri_path$ |




#### Reference

* [https://attack.mitre.org/techniques/T1560/001/](https://attack.mitre.org/techniques/T1560/001/)
* [https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html](https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html)
* [https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/archive_http_post/stream_http_events.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/archive_http_post/stream_http_events.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/network/multiple_archive_files_http_post_traffic.yml) \| *version*: **1**