---
title: "Ingress Tool Transfer"
last_modified_at: 2021-03-24
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP.

- **ID**: b3782036-8cbd-11eb-9d8e-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-24
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadFile](/endpoint/any_powershell_downloadfile/) | None | TTP |
| [Any Powershell DownloadString](/endpoint/any_powershell_downloadstring/) | None | TTP |
| [BITSAdmin Download File](/endpoint/bitsadmin_download_file/) | None | TTP |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/certutil_download_with_urlcache_and_split_arguments/) | None | TTP |
| [CertUtil Download With VerifyCtl and Split Arguments](/endpoint/certutil_download_with_verifyctl_and_split_arguments/) | None | TTP |
| [Suspicious Curl Network Connection](/endpoint/suspicious_curl_network_connection/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



_version_: 1