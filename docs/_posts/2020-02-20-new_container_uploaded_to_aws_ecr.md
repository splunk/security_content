---
title: "New container uploaded to AWS ECR"
excerpt: "Implant Internal Image
"
categories:
  - Cloud
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

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This searches show information on uploaded containers including source user, image id, source IP user type, http user agent, region, first time, last time of operation (PutImage). These searches are based on Cloud Infrastructure Data Model.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-02-20
- **Author**: Rod Soto, Rico Valdez, Splunk
- **ID**: f0f70b40-f7ad-489d-9905-23d149da8099


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1525](https://attack.mitre.org/techniques/T1525/) | Implant Internal Image | Persistence |

#### Search

```

| tstats count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Cloud_Infrastructure.Compute where Compute.user_type!="AssumeRole" AND Compute.http_user_agent="AWS Internal" AND Compute.event_name="PutImage" by Compute.image_id Compute.src_user Compute.src Compute.region Compute.msg Compute.user_type 
| `drop_dm_object_name("Compute")` 
| `new_container_uploaded_to_aws_ecr_filter` 
```

#### Macros
The SPL above uses the following Macros:

Note that `new_container_uploaded_to_aws_ecr_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. You must also install Cloud Infrastructure data model. Please also customize the `container_implant_aws_detection_filter` macro to filter out the false positives.

#### Known False Positives
Uploading container is a normal behavior from developers or users with access to container registry.

#### Associated Analytic story
* [Container Implantation Monitoring and Investigation](/stories/container_implantation_monitoring_and_investigation)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/new_container_uploaded_to_aws_ecr.yml) \| *version*: **1**