---
title: "Ransomware Investigate and Contain"
last_modified_at: 2018-02-04
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - Carbon Black Response
  - LDAP
  - Palo Alto Networks Firewall
  - WildFire
  - Cylance
  - Ransomware
  - Response
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This playbook investigates and contains ransomware detected on endpoints.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [Carbon Black Response](https://splunkbase.splunk.com/apps/#/search/Carbon Black Response/product/soar), [LDAP](https://splunkbase.splunk.com/apps/#/search/LDAP/product/soar), [Palo Alto Networks Firewall](https://splunkbase.splunk.com/apps/#/search/Palo Alto Networks Firewall/product/soar), [WildFire](https://splunkbase.splunk.com/apps/#/search/WildFire/product/soar), [Cylance](https://splunkbase.splunk.com/apps/#/search/Cylance/product/soar)
- **Last Updated**: 2018-02-04
- **Author**: Philip Royer, Splunk
- **ID**: fc0edc96-ff2b-48b0-9f6f-63da3783fd63

#### Associated Detections

* [Attempted Credential Dump From Registry via Reg exe](/detection/attempted_credential_dump_from_registry_via_reg_exe/)



#### How To Implement
This playbook requires the Splunk SOAR apps for Palo Alto Networks Firewalls, Palo Alto Wildfire, LDAP, and Carbon Black Response.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/ransomware_investigate_and_contain.png)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/ransomware_investigate_and_contain.yml) \| *version*: **1**