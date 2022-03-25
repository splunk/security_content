---
title: "Executables Or Script Creation In Suspicious Path"
excerpt: "Masquerading
"
categories:
  - Endpoint
last_modified_at: 2021-05-06
toc: true
toc_label: ""
tags:
  - Masquerading
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will identify suspicious executable or scripts (known file extensions) in list of suspicious file path in Windows. This technique is used by adversaries to evade detection. The suspicious file path are known paths used in the wild and are not common to have executable or scripts.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-05-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: a7e3f0f0-ae42-11eb-b245-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Defense Evasion |

#### Search

```

|tstats `security_content_summariesonly` values(Filesystem.file_path) as file_path count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name = *.exe OR Filesystem.file_name = *.dll OR Filesystem.file_name = *.sys OR Filesystem.file_name = *.com OR Filesystem.file_name = *.vbs OR Filesystem.file_name = *.vbe OR Filesystem.file_name = *.js OR Filesystem.file_name = *.ps1 OR Filesystem.file_name = *.bat OR Filesystem.file_name = *.cmd OR Filesystem.file_name = *.pif) AND ( Filesystem.file_path = *\\windows\\fonts\\* OR Filesystem.file_path = *\\windows\\temp\\* OR Filesystem.file_path = *\\users\\public\\* OR Filesystem.file_path = *\\windows\\debug\\* OR Filesystem.file_path = *\\Users\\Administrator\\Music\\* OR Filesystem.file_path = *\\Windows\\servicing\\* OR Filesystem.file_path = *\\Users\\Default\\* OR Filesystem.file_path = *Recycle.bin* OR Filesystem.file_path = *\\Windows\\Media\\* OR Filesystem.file_path = *\\Windows\\repair\\* OR Filesystem.file_path = *\\AppData\\Local\\Temp* OR Filesystem.file_path = *\\PerfLogs\\*) by Filesystem.file_create_time Filesystem.process_id  Filesystem.file_name Filesystem.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `executables_or_script_creation_in_suspicious_path_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `executables_or_script_creation_in_suspicious_path_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.file_path
* Filesystem.file_create_time
* Filesystem.process_id
* Filesystem.file_name
* Filesystem.user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the Filesystem responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesystem` node.

#### Known False Positives
Administrators may allow creation of script or exe in the paths specified. Filter as needed.

#### Associated Analytic story
* [XMRig](/stories/xmrig)
* [Remcos](/stories/remcos)
* [WhisperGate](/stories/whispergate)
* [Hermetic Wiper](/stories/hermetic_wiper)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 80 | 70 | Suspicious executable or scripts with file name $file_name$, $file_path$ and process_id $process_id$ executed in suspicious file path in Windows by $user$ |




#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/executables_or_script_creation_in_suspicious_path.yml) \| *version*: **1**