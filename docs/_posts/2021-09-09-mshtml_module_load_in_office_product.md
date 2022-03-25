---
title: "MSHTML Module Load in Office Product"
excerpt: "Phishing
, Spearphishing Attachment
"
categories:
  - Endpoint
last_modified_at: 2021-09-09
toc: true
toc_label: ""
tags:
  - Phishing
  - Spearphishing Attachment
  - Initial Access
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-40444
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following detection identifies the module load of mshtml.dll into an Office product. This behavior has been related to CVE-2021-40444, whereas the malicious document will load ActiveX, which activates the MSHTML component. The vulnerability resides in the MSHTML component. During triage, identify parallel processes and capture any file modifications for analysis.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-09-09
- **Author**: Michael Haag, Splunk
- **ID**: 5f1c168e-118b-11ec-84ff-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

#### Search

```
`sysmon` EventID=7  process_name IN ("winword.exe","excel.exe","powerpnt.exe","mspub.exe","visio.exe","wordpad.exe","wordview.exe") ImageLoaded IN ("*\\mshtml.dll", "*\\Microsoft.mshtml.dll","*\\IE.Interop.MSHTML.dll","*\\MshtmlDac.dll","*\\MshtmlDed.dll","*\\MshtmlDer.dll") 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, process_name, ImageLoaded, OriginalFileName, process_id 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `mshtml_module_load_in_office_product_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `mshtml_module_load_in_office_product_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ImageLoaded
* process_name
* OriginalFileName
* process_id
* dest


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process names and image loads from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Limited false positives will be present, however, tune as necessary.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)
* [Microsoft MSHTML Remote Code Execution CVE-2021-40444](/stories/microsoft_mshtml_remote_code_execution_cve-2021-40444)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $process_name$ was identified on endpoint $dest$ loading mshtml.dll. |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-40444](https://nvd.nist.gov/vuln/detail/CVE-2021-40444) | Microsoft MSHTML Remote Code Execution Vulnerability | 6.8 |



#### Reference

* [https://app.any.run/tasks/36c14029-9df8-439c-bba0-45f2643b0c70/](https://app.any.run/tasks/36c14029-9df8-439c-bba0-45f2643b0c70/)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)
* [https://strontic.github.io/xcyclopedia/index-dll](https://strontic.github.io/xcyclopedia/index-dll)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_mshtml.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_mshtml.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/mshtml_module_load_in_office_product.yml) \| *version*: **1**