---
title: "File with Samsam Extension"
excerpt: ""
categories:
  - Endpoint
last_modified_at: 2018-12-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for file writes with extensions consistent with a SamSam ransomware attack.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2018-12-14
- **Author**: Rico Valdez, Splunk
- **ID**: 02c6cfc2-ae66-4735-bfc7-6291da834cbf

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.dest) as dest values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem by Filesystem.file_name 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)`
| rex field=file_name "(?<file_extension>\.[^\.]+)$" 
| search file_extension=.stubbin OR file_extension=.berkshire OR file_extension=.satoshi OR file_extension=.sophos OR file_extension=.keyxml 
| `file_with_samsam_extension_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `file_with_samsam_extension_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.user
* Filesystem.dest
* Filesystem.file_path
* Filesystem.file_name


#### How To Implement
You must be ingesting data that records file-system activity from your hosts to populate the Endpoint file-system data-model node. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data.

#### Known False Positives
Because these extensions are not typically used in normal operations, you should investigate all results.

#### Associated Analytic story
* [SamSam Ransomware](/stories/samsam_ransomware)


#### Kill Chain Phase
* Installation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 100 | 90 | File writes $file_name$ with extensions consistent with a SamSam ransomware attack seen on $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/samsam_extension/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/samsam_extension/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/file_with_samsam_extension.yml) \| *version*: **1**