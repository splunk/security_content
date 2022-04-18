---
title: "Gsuite Outbound Email With Attachment To External Domain"
excerpt: "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
, Exfiltration Over Alternative Protocol
"
categories:
  - Cloud
last_modified_at: 2021-08-17
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
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious outbound e-mail from internal email to external email domain. This can be a good hunting query to monitor insider or outbound email traffic for not common domain e-mail. The idea is to parse the domain of destination email check if there is a minimum outbound traffic < 20 with attachment.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-08-17
- **Author**: Teoderick Contreras, Stanislav Miskovic, Splunk
- **ID**: dc4dc3a8-ff54-11eb-8bf7-acde48001122


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
`gsuite_gmail` num_message_attachments > 0 
| rex field=source.from_header_address "[^@]+@(?<source_domain>[^@]+)" 
| rex field=destination{}.address "[^@]+@(?<dest_domain>[^@]+)" 
| where source_domain="internal_test_email.com" and not dest_domain="internal_test_email.com" 
| eval phase="plan" 
| eval severity="low" 
| stats values(subject) as subject, values(source.from_header_address) as src_domain_list, count as numEvents, dc(source.from_header_address) as numSrcAddresses, min(_time) as firstTime max(_time) as lastTime by dest_domain phase severity 
| where numSrcAddresses < 20 
|sort - numSrcAddresses 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `gsuite_outbound_email_with_attachment_to_external_domain_filter`
```

#### Macros
The SPL above uses the following Macros:
* [gsuite_gmail](https://github.com/splunk/security_content/blob/develop/macros/gsuite_gmail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **gsuite_outbound_email_with_attachment_to_external_domain_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this search, you need to be ingesting logs related to gsuite having the file attachment metadata like file type, file extension, source email, destination email, num of attachment and etc.

#### Known False Positives
network admin and normal user may send this file attachment as part of their day to day work. having a good protocol in attaching this file type to an e-mail may reduce the risk of having a spear phishing attack.

#### Associated Analytic story
* [Dev Sec Ops](/stories/dev_sec_ops)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | suspicious email from $source.address$ to $destination{}.address$ |


#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_outbound_email_to_external/gsuite_external_domain.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_outbound_email_to_external/gsuite_external_domain.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/gsuite_outbound_email_with_attachment_to_external_domain.yml) \| *version*: **1**