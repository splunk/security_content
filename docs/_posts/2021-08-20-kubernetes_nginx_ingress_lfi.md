---
title: "Kubernetes Nginx Ingress LFI"
excerpt: "Exploitation for Credential Access"
categories:
  - Cloud
last_modified_at: 2021-08-20
toc: true
toc_label: ""
tags:
  - Exploitation for Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search uses the Kubernetes logs from a nginx ingress controller to detect local file inclusion attacks.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-08-20
- **Author**: Patrick Bareiss, Splunk
- **ID**: 0f83244b-425b-4528-83db-7a88c5f66e48


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1212](https://attack.mitre.org/techniques/T1212/) | Exploitation for Credential Access | Credential Access |

#### Search

```
`kubernetes_container_controller` 
| rex field=_raw "^(?<remote_addr>\S+)\s+-\s+-\s+\[(?<time_local>[^\]]*)\]\s\"(?<request>[^\"]*)\"\s(?<status>\S*)\s(?<body_bytes_sent>\S*)\s\"(?<http_referer>[^\"]*)\"\s\"(?<http_user_agent>[^\"]*)\"\s(?<request_length>\S*)\s(?<request_time>\S*)\s\[(?<proxy_upstream_name>[^\]]*)\]\s\[(?<proxy_alternative_upstream_name>[^\]]*)\]\s(?<upstream_addr>\S*)\s(?<upstream_response_length>\S*)\s(?<upstream_response_time>\S*)\s(?<upstream_status>\S*)\s(?<req_id>\S*)" 
| lookup local_file_inclusion_paths local_file_inclusion_paths AS request OUTPUT lfi_path 
| search lfi_path=yes 
| rename remote_addr AS src_ip, upstream_status as status, proxy_upstream_name as proxy 
| rex field=request "^(?<http_method>\S+)\s(?<url>\S+)\s" 
| eval phase="operate" 
| eval severity="high" 
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip, status, url, http_method, host, http_user_agent, proxy, phase, severity 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `kubernetes_nginx_ingress_lfi_filter`
```

#### Associated Analytic Story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### How To Implement
You must ingest Kubernetes logs through Splunk Connect for Kubernetes.

#### Required field
* raw


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Local File Inclusion Attack detected on $host$ |




#### Reference

* [https://github.com/splunk/splunk-connect-for-kubernetes](https://github.com/splunk/splunk-connect-for-kubernetes)
* [https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/](https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1212/kubernetes_nginx_lfi_attack/kubernetes_nginx_lfi_attack.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1212/kubernetes_nginx_lfi_attack/kubernetes_nginx_lfi_attack.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/kubernetes_nginx_ingress_lfi.yml) \| *version*: **1**