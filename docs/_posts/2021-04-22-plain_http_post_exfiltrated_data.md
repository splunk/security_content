---
title: "Plain HTTP POST Exfiltrated Data"
excerpt: "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
, Exfiltration Over Alternative Protocol
"
categories:
  - Network
last_modified_at: 2021-04-22
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

This search is to detect potential plain HTTP POST method data exfiltration. This network traffic is commonly used by trickbot, trojanspy, keylogger or APT adversary where arguments or commands are sent in plain text to the remote C2 server using HTTP POST method as part of data exfiltration.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-04-22
- **Author**: Teoderick Contreras, Splunk
- **ID**: e2b36208-a364-11eb-8909-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |

| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Exfiltration |

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
`stream_http` http_method=POST form_data IN ("*wermgr.exe*","*svchost.exe*", "*name=\"proclist\"*","*ipconfig*", "*name=\"sysinfo\"*", "*net view*") 
|stats values(form_data) as http_request_body min(_time) as firstTime max(_time) as lastTime count by http_method http_user_agent uri_path url bytes_in bytes_out 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `plain_http_post_exfiltrated_data_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [stream_http](https://github.com/splunk/security_content/blob/develop/macros/stream_http.yml)

Note that **plain_http_post_exfiltrated_data_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* http_method
* http_user_agent
* uri_path
* url
* bytes_in
* bytes_out


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the stream HTTP logs or network logs that catch network traffic. Make sure that the http-request-body, payload, or request field is enabled.

#### Known False Positives
unknown

#### Associated Analytic story
* [Data Exfiltration](/stories/data_exfiltration)
* [Command and Control](/stories/command_and_control)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A http post $http_method$ sending packet with plain text of information $form_data$ in uri path $uri_path$ |


#### Reference

* [https://blog.talosintelligence.com/2020/03/trickbot-primer.html](https://blog.talosintelligence.com/2020/03/trickbot-primer.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/plain_exfil_data/stream_http_events.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/plain_exfil_data/stream_http_events.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/network/plain_http_post_exfiltrated_data.yml) \| *version*: **1**