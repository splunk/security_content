---
title: "PetitPotam NTLM Relay on Active Directory Certificate Services"
last_modified_at: 2021-08-31
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

PetitPotam (CVE-2021-36942,) is a vulnerablity identified in Microsofts EFSRPC Protocol that can allow an unauthenticated account to escalate privileges to domain administrator given the right circumstances.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-08-31
- **Author**: Michael Haag, Mauricio Velazco, Splunk
- **ID**: 97aecafc-0a68-11ec-962f-acde48001122

#### Narrative

In June 2021, security researchers at SpecterOps released a blog post and white paper detailing several potential attack vectors against Active Directory Certificated Services (ADCS). ADCS is a Microsoft product that implements Public Key Infrastrucutre (PKI) functionality and can be used by organizations to provide and manage digital certiticates within Active Directory.\ In July 2021, a security researcher released PetitPotam, a tool that allows attackers to coerce Windows systems into authenticating to arbitrary endpoints.\ Combining PetitPotam with the identified ADCS attack vectors allows attackers to escalate privileges from an unauthenticated anonymous user to full domain admin privileges.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [PetitPotam Network Share Access Request](/endpoint/petitpotam_network_share_access_request/) | [Forced Authentication](/tags/#forced-authentication)| TTP |
| [PetitPotam Suspicious Kerberos TGT Request](/endpoint/petitpotam_suspicious_kerberos_tgt_request/) | [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |

#### Reference

* [https://us-cert.cisa.gov/ncas/current-activity/2021/07/27/microsoft-releases-guidance-mitigating-petitpotam-ntlm-relay](https://us-cert.cisa.gov/ncas/current-activity/2021/07/27/microsoft-releases-guidance-mitigating-petitpotam-ntlm-relay)
* [https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)
* [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
* [https://github.com/topotam/PetitPotam/](https://github.com/topotam/PetitPotam/)
* [https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20210723](https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20210723)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)
* [https://attack.mitre.org/techniques/T1187/](https://attack.mitre.org/techniques/T1187/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/petitpotam_ntlm_relay_on_active_directory_certificate_services.yml) \| *version*: **1**