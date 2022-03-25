---
title: "Office Product Writing cab or inf"
excerpt: "Phishing
, Spearphishing Attachment
"
categories:
  - Endpoint
last_modified_at: 2021-09-10
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

The following analytic identifies behavior related to CVE-2021-40444. Whereas the malicious document will load ActiveX and download the remote payload (.inf, .cab). During triage, review parallel processes and further activity on endpoint to identify additional patterns. Retrieve the file modifications and analyze further.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-09-10
- **Author**: Michael Haag, Splunk
- **ID**: f48cd1d4-125a-11ec-a447-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name IN ("winword.exe","excel.exe","powerpnt.exe","mspub.exe","visio.exe","wordpad.exe","wordview.exe") by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest 
| `drop_dm_object_name(Processes)` 
| join process_guid, _time [
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("*.inf","*.cab") by _time span=1h Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| fields _time dest file_create_time file_name file_path process_name process_path process] 
| dedup file_create_time 
| table dest, process_name, process, file_create_time, file_name, file_path 
| `office_product_writing_cab_or_inf_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `office_product_writing_cab_or_inf_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* process_name
* process
* file_create_time
* file_name
* file_path


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node and `Filesystem` node.

#### Known False Positives
The query is structured in a way that `action` (read, create) is not defined. Review the results of this query, filter, and tune as necessary. It may be necessary to generate this query specific to your endpoint product.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)
* [Microsoft MSHTML Remote Code Execution CVE-2021-40444](/stories/microsoft_mshtml_remote_code_execution_cve-2021-40444)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $process_name$ was identified on $dest$ writing an inf or cab file to this. This is not typical of $process_name$. |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-40444](https://nvd.nist.gov/vuln/detail/CVE-2021-40444) | Microsoft MSHTML Remote Code Execution Vulnerability | 6.8 |



#### Reference

* [https://twitter.com/vxunderground/status/1436326057179860992?s=20](https://twitter.com/vxunderground/status/1436326057179860992?s=20)
* [https://app.any.run/tasks/36c14029-9df8-439c-bba0-45f2643b0c70/](https://app.any.run/tasks/36c14029-9df8-439c-bba0-45f2643b0c70/)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)
* [https://twitter.com/RonnyTNL/status/1436334640617373699?s=20](https://twitter.com/RonnyTNL/status/1436334640617373699?s=20)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_cabinf.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_cabinf.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_product_writing_cab_or_inf.yml) \| *version*: **1**