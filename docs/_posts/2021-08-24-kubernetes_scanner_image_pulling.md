---
title: "Kubernetes Scanner Image Pulling"
excerpt: "Cloud Service Discovery"
categories:
  - Cloud
last_modified_at: 2021-08-24
toc: true
toc_label: ""
tags:
  - Cloud Service Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search uses the Kubernetes logs from Splunk Connect from Kubernetes to detect Kubernetes Security Scanner.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-08-24
- **Author**: Patrick Bareiss, Splunk
- **ID**: 4890cd6b-0112-4974-a272-c5c153aee551


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1526](https://attack.mitre.org/techniques/T1526/) | Cloud Service Discovery | Discovery |

#### Search

```
`kube_objects_events` object.message IN ("Pulling image *kube-hunter*", "Pulling image *kube-bench*", "Pulling image *kube-recon*", "Pulling image *kube-recon*") 
| rename object.* AS * 
| rename involvedObject.* AS * 
| rename source.host AS host 
| eval phase="operate" 
| eval severity="high" 
| stats min(_time) as firstTime max(_time) as lastTime count by host, name, namespace, kind, reason, message, phase, severity 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `kubernetes_scanner_image_pulling_filter`
```

#### Associated Analytic Story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### How To Implement
You must ingest Kubernetes logs through Splunk Connect for Kubernetes.

#### Required field
* object.message
* source.host
* object.involvedObject.name
* object.involvedObject.namespace
* object.involvedObject.kind
* object.message
* object.reason


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | Kubernetes Scanner image pulled on host $host$ |




#### Reference

* [https://github.com/splunk/splunk-connect-for-kubernetes](https://github.com/splunk/splunk-connect-for-kubernetes)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1526/kubernetes_kube_hunter/kubernetes_kube_hunter.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1526/kubernetes_kube_hunter/kubernetes_kube_hunter.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/kubernetes_scanner_image_pulling.yml) \| *version*: **1**