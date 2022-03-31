---
title: "Gdrive suspicious file sharing"
excerpt: "Phishing
"
categories:
  - Cloud
last_modified_at: 2021-10-24
toc: true
toc_label: ""
tags:
  - Phishing
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search can help the detection of compromised accounts or internal users sharing potentially malicious/classified documents with users outside your organization via GSuite file sharing .

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-10-24
- **Author**: Rod Soto, Teoderick Contreras
- **ID**: a7131dae-34e3-11ec-a2de-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

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
`gsuite_drive` name=change_user_access 
| rename parameters.* as * 
| search email = "*@yourdomain.com" target_user != "*@yourdomain.com" 
| stats count values(owner) as owner values(target_user) as target values(doc_type) as doc_type values(doc_title) as doc_title dc(target_user) as distinct_target by src_ip email 
| where distinct_target > 50 
| `gdrive_suspicious_file_sharing_filter`
```

#### Macros
The SPL above uses the following Macros:
* [gsuite_drive](https://github.com/splunk/security_content/blob/develop/macros/gsuite_drive.yml)

Note that **gdrive_suspicious_file_sharing_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* src_ip
* parameters.owner
* parameters.target_user
* parameters.doc_title
* parameters.doc_type


#### How To Implement
Need to implement Gsuite logging targeting Google suite drive activity. In order for the search to work for your environment please update `yourdomain.com` value in the query with the domain relavant for your organization.

#### Known False Positives
This is an anomaly search, you must specify your domain in the parameters so it either filters outside domains or focus on internal domains. This search may also help investigate compromise of accounts. By looking at for example source ip addresses, document titles and abnormal number of shares and shared target users.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)
* [Data Exfiltration](/stories/data_exfiltration)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference

* [https://www.splunk.com/en_us/blog/security/investigating-gsuite-phishing-attacks-with-splunk.html](https://www.splunk.com/en_us/blog/security/investigating-gsuite-phishing-attacks-with-splunk.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [[]]([])



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/gdrive_suspicious_file_sharing.yml) \| *version*: **1**