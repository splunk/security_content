---
title: "Cloud Network Access Control List Deleted"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2020-09-08
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Enforcing network-access controls is one of the defensive mechanisms used by cloud administrators to restrict access to a cloud instance. After the attacker has gained control of the console by compromising an admin account, they can delete a network ACL and gain access to the instance from anywhere. This search will query the Change datamodel to detect users deleting network ACLs. Deprecated because it's a duplicate

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2020-09-08
- **Author**: Peter Gael, Splunk
- **ID**: 021abc51-1862-41dd-ad43-43c739c0a983


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

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

* DE.DP
* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 11



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudtrail` eventName=DeleteNetworkAcl
|rename userIdentity.arn as arn  
| stats count min(_time) as firstTime max(_time) as lastTime values(errorMessage) values(errorCode) values(userAgent) values(userIdentity.*) by src userName arn eventName 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `cloud_network_access_control_list_deleted_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **cloud_network_access_control_list_deleted_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* userIdentity.arn
* errorMessage
* errorCode
* userAgent
* src
* userName
* arn


#### How To Implement
You must be ingesting your cloud infrastructure logs from your cloud provider. You can also provide additional filtering for this search by customizing the `cloud_network_access_control_list_deleted_filter` macro.

#### Known False Positives
It's possible that a user has legitimately deleted a network ACL.

#### Associated Analytic story
* [Cloud Network ACL Activity](/stories/cloud_network_acl_activity)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/cloud_network_access_control_list_deleted.yml) \| *version*: **1**