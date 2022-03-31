---
title: "High Frequency Copy Of Files In Network Share"
excerpt: "Transfer Data to Cloud Account
"
categories:
  - Endpoint
last_modified_at: 2021-11-16
toc: true
toc_label: ""
tags:
  - Transfer Data to Cloud Account
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious high frequency copying/moving of files in network share as part of information sabotage. This anomaly event can be a good indicator of insider trying to sabotage data by transfering classified or internal files within network share to exfitrate it after or to lure evidence of insider attack to other user. This behavior may catch several noise if network share is a common place for classified or internal document processing.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-16
- **Author**: Teoderick Contreras, Splunk
- **ID**: 40925f12-4709-11ec-bb43-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1537](https://attack.mitre.org/techniques/T1537/) | Transfer Data to Cloud Account | Exfiltration |

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
`wineventlog_security` EventCode=5145 Relative_Target_Name IN ("*.doc","*.docx","*.xls","*.xlsx","*.ppt","*.pptx","*.log","*.txt","*.db","*.7z","*.zip","*.rar","*.tar","*.gz","*.jpg","*.gif","*.png","*.bmp","*.pdf","*.rtf","*.key") Object_Type=File Share_Name IN ("\\\\*\\C$","\\\\*\\IPC$","\\\\*\\admin$") Access_Mask= "0x2" 
|  bucket _time span=5m 
| stats values(Relative_Target_Name) as valRelativeTargetName, values(Share_Name) as valShareName, values(Object_Type) as valObjectType, values(Access_Mask) as valAccessmask, values(src_port) as valSrcPort, values(Source_Address) as valSrcAddress count as numShareName by dest, _time, EventCode, user 
| eventstats avg(numShareName) as avgShareName, stdev(numShareName) as stdShareName, count as numSlots by dest, _time, EventCode, user 
|  eval upperThreshold=(avgShareName + stdShareName *3) 
|  eval isOutlier=if(avgShareName > 20 and avgShareName >= upperThreshold, 1, 0) 
|  search isOutlier=1 
| `high_frequency_copy_of_files_in_network_share_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that **high_frequency_copy_of_files_in_network_share_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Share_Name
* Relative_Target_Name
* Object_Type
* Access_Mask
* user
* src_port
* Source_Address


#### How To Implement
o successfully implement this search, you need to be ingesting Windows Security Event Logs with 5145 EventCode enabled. The Windows TA is also required. Also enable the object Audit access success/failure in your group policy.

#### Known False Positives
this behavior may seen in normal transfer of file within network if network share is common place for sharing documents.

#### Associated Analytic story
* [Information Sabotage](/stories/information_sabotage)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | high frequency copy of document in network share $Share_Name$ from $Source_Address$ by $user$ |


#### Reference

* [https://attack.mitre.org/techniques/T1537/](https://attack.mitre.org/techniques/T1537/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/high_copy_files_in_net_share/security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/high_copy_files_in_net_share/security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/high_frequency_copy_of_files_in_network_share.yml) \| *version*: **1**