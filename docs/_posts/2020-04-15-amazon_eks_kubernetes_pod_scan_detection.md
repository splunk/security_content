---
title: "Amazon EKS Kubernetes Pod scan detection"
excerpt: "Cloud Service Discovery"
categories:
  - Cloud
last_modified_at: 2020-04-15
toc: true
toc_label: ""
tags:
  - Cloud Service Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection information on unauthenticated requests against Kubernetes&#39; Pods API

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-04-15
- **Author**: Rod Soto, Splunk
- **ID**: dbfca1dd-b8e5-4ba4-be0e-e565e5d62002


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1526](https://attack.mitre.org/techniques/T1526/) | Cloud Service Discovery | Discovery |

#### Search

```
`aws_cloudwatchlogs_eks` "user.username"="system:anonymous" verb=list objectRef.resource=pods requestURI="/api/v1/pods" 
| rename source as cluster_name sourceIPs{} as src_ip 
| stats count min(_time) as firstTime max(_time) as lastTime values(responseStatus.reason) values(responseStatus.code) values(userAgent) values(verb) values(requestURI) by src_ip cluster_name user.username user.groups{} 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `amazon_eks_kubernetes_pod_scan_detection_filter` 
```

#### Associated Analytic Story
* [Kubernetes Scanning Activity](/stories/kubernetes_scanning_activity)


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on forAWS (version 4.4.0 or later), then configure your AWS CloudWatch EKS Logs.Please also customize the `kubernetes_pods_aws_scan_fingerprint_detection` macro to filter out the false positives.

#### Required field
* _time
* user.username
* verb
* objectRef.resource
* requestURI
* source
* sourceIPs{}
* responseStatus.reason
* responseStatus.code
* userAgent
* src_ip
* user.groups{}


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
Not all unauthenticated requests are malicious, but frequency, UA and source IPs and direct request to API provide context.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/amazon_eks_kubernetes_pod_scan_detection.yml) \| *version*: **1**