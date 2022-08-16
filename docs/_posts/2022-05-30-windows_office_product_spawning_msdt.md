---
title: "Windows Office Product Spawning MSDT"
excerpt: "Phishing
, Spearphishing Attachment
"
categories:
  - Endpoint
last_modified_at: 2022-05-30
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
  - CVE-2022-30190
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a Microsoft Office product spawning the Windows msdt.exe process. MSDT is a Diagnostics Troubleshooting Wizard native to Windows. This behavior is related to a recently identified sample utilizing protocol handlers to evade preventative controls, including if macros are disabled in the document. During triage, review file modifications for html. In addition, parallel processes including PowerShell and CertUtil.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-05-30
- **Author**: Michael Haag, Teoderick Contreras, Splunk
- **ID**: 127eba64-c981-40bf-8589-1830638864a7


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2022-30190](https://nvd.nist.gov/vuln/detail/CVE-2022-30190) | Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability. | 9.3 |



</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","mspub.exe","visio.exe") Processes.process_name=msdt.exe by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `windows_office_product_spawning_msdt_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_office_product_spawning_msdt_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
how To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited, however filter as needed.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)
* [Microsoft Support Diagnostic Tool Vulnerability CVE-2022-30190](/stories/microsoft_support_diagnostic_tool_vulnerability_cve-2022-30190)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 100.0 | 100 | 100 | Office parent process $parent_process_name$ has spawned a child process $process_name$ on host $dest$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://isc.sans.edu/diary/rss/28694](https://isc.sans.edu/diary/rss/28694)
* [https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e](https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e)
* [https://twitter.com/nao_sec/status/1530196847679401984?s=20&t=ZiXYI4dQuA-0_dzQzSUb3A](https://twitter.com/nao_sec/status/1530196847679401984?s=20&t=ZiXYI4dQuA-0_dzQzSUb3A)
* [https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/](https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/)
* [https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/detection](https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/detection)
* [https://strontic.github.io/xcyclopedia/library/msdt.exe-152D4C9F63EFB332CCB134C6953C0104.html](https://strontic.github.io/xcyclopedia/library/msdt.exe-152D4C9F63EFB332CCB134C6953C0104.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/msdt.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/msdt.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_office_product_spawning_msdt.yml) \| *version*: **1**