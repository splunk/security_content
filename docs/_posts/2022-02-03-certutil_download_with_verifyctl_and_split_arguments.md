---
title: "CertUtil Download With VerifyCtl and Split Arguments"
excerpt: "Ingress Tool Transfer
"
categories:
  - Endpoint
last_modified_at: 2022-02-03
toc: true
toc_label: ""
tags:
  - Ingress Tool Transfer
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Certutil.exe may download a file from a remote destination using `-VerifyCtl`. This behavior does require a URL to be passed on the command-line. In addition, `-f` (force) and `-split` (Split embedded ASN.1 elements, and save to files) will be used. It is not entirely common for `certutil.exe` to contact public IP space. \ During triage, capture any files on disk and review. Review the reputation of the remote IP or domain in question. Using `-VerifyCtl`, the file will either be written to the current working directory or `%APPDATA%\..\LocalLow\Microsoft\CryptnetUrlCache\Content\<hash>`. 

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-02-03
- **Author**: Michael Haag, Splunk
- **ID**: 801ad9e4-8bfb-11eb-8b31-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_certutil` (Processes.process=*verifyctl* Processes.process=*split*) OR Processes.process=*verifyctl* by Processes.dest Processes.user Processes.original_file_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `certutil_download_with_verifyctl_and_split_arguments_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_certutil](https://github.com/splunk/security_content/blob/develop/macros/process_certutil.yml)

Note that `certutil_download_with_verifyctl_and_split_arguments_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Limited false positives in most environments, however tune as needed based on parent-child relationship or network connection.

#### Associated Analytic story
* [Ingress Tool Transfer](/stories/ingress_tool_transfer)
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to download a file. |




#### Reference

* [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)
* [https://www.hexacorn.com/blog/2020/08/23/certutil-one-more-gui-lolbin/](https://www.hexacorn.com/blog/2020/08/23/certutil-one-more-gui-lolbin/)
* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732443(v=ws.11)#-verifyctl](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc732443(v=ws.11)#-verifyctl)
* [https://www.avira.com/en/blog/certutil-abused-by-attackers-to-spread-threats](https://www.avira.com/en/blog/certutil-abused-by-attackers-to-spread-threats)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/certutil_download_with_verifyctl_and_split_arguments.yml) \| *version*: **3**