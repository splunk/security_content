---
title: "Detect New Open GCP Storage Buckets"
excerpt: "Data from Cloud Storage Object
"
categories:
  - Cloud
last_modified_at: 2020-08-05
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

This search looks for GCP PubSub events where a user has created an open/public GCP Storage bucket.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-08-05
- **Author**: Shannon Davis, Splunk
- **ID**: f6ea3466-d6bb-11ea-87d0-0242ac130003


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



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`google_gcp_pubsub_message` data.resource.type=gcs_bucket data.protoPayload.methodName=storage.setIamPermissions 
| spath output=action path=data.protoPayload.serviceData.policyDelta.bindingDeltas{}.action 
| spath output=user path=data.protoPayload.authenticationInfo.principalEmail 
| spath output=location path=data.protoPayload.resourceLocation.currentLocations{} 
| spath output=src path=data.protoPayload.requestMetadata.callerIp 
| spath output=bucketName path=data.protoPayload.resourceName 
| spath output=role path=data.protoPayload.serviceData.policyDelta.bindingDeltas{}.role 
| spath output=member path=data.protoPayload.serviceData.policyDelta.bindingDeltas{}.member 
| search (member=allUsers AND action=ADD) 
| table  _time, bucketName, src, user, location, action, role, member 
| search `detect_new_open_gcp_storage_buckets_filter`
```

#### Macros
The SPL above uses the following Macros:
* [google_gcp_pubsub_message](https://github.com/splunk/security_content/blob/develop/macros/google_gcp_pubsub_message.yml)

Note that **detect_new_open_gcp_storage_buckets_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* data.resource.type
* data.protoPayload.methodName
* data.protoPayload.serviceData.policyDelta.bindingDeltas{}.action
* data.protoPayload.authenticationInfo.principalEmail
* data.protoPayload.resourceLocation.currentLocations{}
* data.protoPayload.requestMetadata.callerIp
* data.protoPayload.resourceName
* data.protoPayload.serviceData.policyDelta.bindingDeltas{}.role
* data.protoPayload.serviceData.policyDelta.bindingDeltas{}.member


#### How To Implement
This search relies on the Splunk Add-on for Google Cloud Platform, setting up a Cloud Pub/Sub input, along with the relevant GCP PubSub topics and logging sink to capture GCP Storage Bucket events (https://cloud.google.com/logging/docs/routing/overview).

#### Known False Positives
While this search has no known false positives, it is possible that a GCP admin has legitimately created a public bucket for a specific purpose. That said, GCP strongly advises against granting full control to the "allUsers" group.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/detect_new_open_gcp_storage_buckets.yml) \| *version*: **1**