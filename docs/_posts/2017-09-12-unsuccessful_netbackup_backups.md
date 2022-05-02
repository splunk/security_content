---
title: "Unsuccessful Netbackup backups"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2017-09-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search gives you the hosts where a backup was attempted and then failed.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2017-09-12
- **Author**: David Dorsey, Splunk
- **ID**: a34aae96-ccf8-4aaa-952c-3ea21444444f


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

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

* PR.IP



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 10



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`netbackup` 
| stats latest(_time) as latestTime by COMPUTERNAME, MESSAGE 
| search MESSAGE="An error occurred, failed to backup." 
| `security_content_ctime(latestTime)` 
| rename COMPUTERNAME as dest, MESSAGE as signature 
| table latestTime, dest, signature 
| `unsuccessful_netbackup_backups_filter`
```

#### Macros
The SPL above uses the following Macros:
* [netbackup](https://github.com/splunk/security_content/blob/develop/macros/netbackup.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **unsuccessful_netbackup_backups_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
To successfully implement this search you need to obtain data from your backup solution, either from the backup logs on your endpoints or from a central server responsible for performing the backups. If you do not use Netbackup, you can modify this search for your specific backup solution.

#### Known False Positives
None identified

#### Associated Analytic story
* [Monitor Backup Solution](/stories/monitor_backup_solution)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/unsuccessful_netbackup_backups.yml) \| *version*: **1**