---
title: "Detect GCP Storage access from a new IP"
excerpt: "Data from Cloud Storage Object
"
categories:
  - Cloud
last_modified_at: 2020-08-10
toc: true
toc_label: ""
tags:
  - Data from Cloud Storage Object
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks at GCP Storage bucket-access logs and detects new or previously unseen remote IP addresses that have successfully accessed a GCP Storage bucket.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-08-10
- **Author**: Shannon Davis, Splunk
- **ID**: ccc3246a-daa1-11ea-87d0-0242ac130022


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage Object | Collection |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.DS
* PR.AC
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 13
* CIS 14



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`google_gcp_pubsub_message` 
| multikv 
| rename sc_status_ as status 
| rename cs_object_ as bucket_name 
| rename c_ip_ as remote_ip 
| rename cs_uri_ as request_uri 
| rename cs_method_ as operation 
| search status="\"200\"" 
| stats earliest(_time) as firstTime latest(_time) as lastTime by bucket_name remote_ip operation request_uri 
| table firstTime, lastTime, bucket_name, remote_ip, operation, request_uri 
| inputlookup append=t previously_seen_gcp_storage_access_from_remote_ip 
| stats min(firstTime) as firstTime, max(lastTime) as lastTime by bucket_name remote_ip operation request_uri 
| outputlookup previously_seen_gcp_storage_access_from_remote_ip 
| eval newIP=if(firstTime >= relative_time(now(),"-70m@m"), 1, 0) 
| where newIP=1 
| eval first_time=strftime(firstTime,"%m/%d/%y %H:%M:%S") 
| eval last_time=strftime(lastTime,"%m/%d/%y %H:%M:%S") 
| table  first_time last_time bucket_name remote_ip operation request_uri 
| `detect_gcp_storage_access_from_a_new_ip_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that **detect_gcp_storage_access_from_a_new_ip_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [previously_seen_gcp_storage_access_from_remote_ip](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_gcp_storage_access_from_remote_ip.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_gcp_storage_access_from_remote_ip.csv)
* [previously_seen_gcp_storage_access_from_remote_ip](https://github.com/splunk/security_content/blob/develop/lookups/previously_seen_gcp_storage_access_from_remote_ip.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/previously_seen_gcp_storage_access_from_remote_ip.csv)

#### Required field
* _time
* sc_status_
* cs_object_
* c_ip_
* cs_uri_
* cs_method_


#### How To Implement
This search relies on the Splunk Add-on for Google Cloud Platform, setting up a Cloud Pub/Sub input, along with the relevant GCP PubSub topics and logging sink to capture GCP Storage Bucket events (https://cloud.google.com/logging/docs/routing/overview). In order to capture public GCP Storage Bucket access logs, you must also enable storage bucket logging to your PubSub Topic as per https://cloud.google.com/storage/docs/access-logs.  These logs are deposited into the nominated Storage Bucket on an hourly basis and typically show up by 15 minutes past the hour.  It is recommended to configure any saved searches or correlation searches in Enterprise Security to run on an hourly basis at 30 minutes past the hour (cron definition of 30 * * * *).  A lookup table (previously_seen_gcp_storage_access_from_remote_ip.csv) stores the previously seen access requests, and is used by this search to determine any newly seen IP addresses accessing the Storage Buckets.

#### Known False Positives
GCP Storage buckets can be accessed from any IP (if the ACLs are open to allow it), as long as it can make a successful connection. This will be a false postive, since the search is looking for a new IP within the past two hours.

#### Associated Analytic story
* [Suspicious GCP Storage Activities](/stories/suspicious_gcp_storage_activities)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/detect_gcp_storage_access_from_a_new_ip.yml) \| *version*: **1**