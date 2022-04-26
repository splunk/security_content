---
title: "GCP GCR container uploaded"
excerpt: "Implant Internal Image
"
categories:
  - Deprecated
last_modified_at: 2020-02-20
toc: true
toc_label: ""
tags:
  - Implant Internal Image
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search show information on uploaded containers including source user, account, action, bucket name event name, http user agent, message and destination path.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-02-20
- **Author**: Rod Soto, Rico Valdez, Splunk
- **ID**: 4f00ca88-e766-4605-ac65-ae51c9fd185b


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1525](https://attack.mitre.org/techniques/T1525/) | Implant Internal Image | Persistence |

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

|tstats count min(_time) as firstTime max(_time) as lastTime  FROM datamodel=Cloud_Infrastructure.Storage where Storage.event_name=storage.objects.create by Storage.src_user Storage.account Storage.action Storage.bucket_name Storage.event_name Storage.http_user_agent Storage.msg Storage.object_path 
| `drop_dm_object_name("Storage")`  
| `gcp_gcr_container_uploaded_filter` 
```

#### Macros
The SPL above uses the following Macros:

Note that **gcp_gcr_container_uploaded_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install the GCP App for Splunk (version 2.0.0 or later), then configure stackdriver and set a subpub subscription to be imported to Splunk. You must also install Cloud Infrastructure data model. Please also customize the `container_implant_gcp_detection_filter` macro to filter out the false positives.

#### Known False Positives
Uploading container is a normal behavior from developers or users with access to container registry. GCP GCR registers container upload as a Storage event, this search must be considered under the context of CONTAINER upload creation which automatically generates a bucket entry for destination path.

#### Associated Analytic story
* [Container Implantation Monitoring and Investigation](/stories/container_implantation_monitoring_and_investigation)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/gcp_gcr_container_uploaded.yml) \| *version*: **1**