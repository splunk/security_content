---
title: "Amazon EKS Kubernetes cluster scan detection"
excerpt: "Cloud Service Discovery"
categories:
  - Cloud
last_modified_at: 2020-04-15
toc: true
tags:
  - Hunting
  - T1526
  - Cloud Service Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Reconnaissance
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides information of unauthenticated requests via user agent, and authentication data against Kubernetes cluster in AWS

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-04-15
- **Author**: Rod Soto, Splunk
- **ID**: 294c4686-63dd-4fe6-93a2-ca807626704a


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1526](https://attack.mitre.org/techniques/T1526/) | Cloud Service Discovery | Discovery |



#### Search

```
`aws_cloudwatchlogs_eks` "user.username"="system:anonymous" userAgent!="AWS Security Scanner" 
| rename sourceIPs{} as src_ip 
| stats count min(_time) as firstTime max(_time) as lastTime values(responseStatus.reason) values(source) as cluster_name values(responseStatus.code) values(userAgent) as http_user_agent values(verb) values(requestURI) by src_ip user.username user.groups{} 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
|`amazon_eks_kubernetes_cluster_scan_detection_filter` 
```

#### Associated Analytic Story
* [Kubernetes Scanning Activity](/stories/kubernetes_scanning_activity)


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your CloudWatch EKS Logs inputs.

#### Required field
* _time
* user.username
* userAgent
* sourceIPs{}
* responseStatus.reason
* source
* responseStatus.code
* verb
* requestURI
* src_ip
* user.groups{}


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
Not all unauthenticated requests are malicious, but frequency, UA and source IPs will provide context.




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/amazon_eks_kubernetes_cluster_scan_detection.yml) \| *version*: **1**