---
title: "Threat Intel Investigate"
last_modified_at: 2021-11-30
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - threat_intel
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This parent playbook collects data and launches appropriate child playbooks to gather threat intelligence information about indicators. After the child playbooks have run, this playbook posts the notes to the container and prompts the analyst to add tags to each enriched indicator based on the intelligence provided.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2021-11-30
- **Author**: Philip Royer, Splunk
- **ID**: fc5adc76-fd2b-48b0-5f6f-63bc3493fd46

#### Associated Detections


#### How To Implement
The prompt is currently sent to the Administrator role, but should be changed to the appropriate user and role. The "list_investigate_playbooks" block fetches playbooks from the local repository with the tags "investigate" and "threat_intel" by default. The playbook "trustar_enrich_indicators" is meant to be used by this playbook, and others can be created to replace it or work alongside it. To add a new input playbook, copy it to the local repository and give it the necessary tags. Define a playbook input with the name "indicators" and the data type matching the types of indicators the playbook can process. To add a new tag to the preconfigured list, add it to the "choices" array in the "threat_intel_indicator_review" prompt block, and add it to the "response_to_tag_map" in "process_indicators".

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/threat_intel_investigate.png)

#### Required field


#### Reference

* [https://www.splunk.com/en_us/blog/security/TruSTAR-Enrich-Indicators-soar-in-seconds.html](https://www.splunk.com/en_us/blog/security/TruSTAR-Enrich-Indicators-soar-in-seconds.html)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/threat_intel_investigate.yml) \| *version*: **1**