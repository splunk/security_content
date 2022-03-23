---
title: "Risk Notable Import Data"
last_modified_at: 2021-10-22
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Splunk
  - Risk Notable
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This playbook gathers all of the events associated with the risk notable and imports them as artifacts. It also generates a custom markdown formatted note.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)
- **Last Updated**: 2021-10-22
- **Author**: Kelby Shelton, Splunk
- **ID**: rn0edc96-ff2b-48b0-9f6f-23da3783fd63

#### Associated Detections


#### How To Implement
The Splunk search used to locate contributing events requires three fields in the notable artifact\: risk_object, info_min_time, and info_max_time. The query also performs some deduplication on contributing events and may need to be adjusted based on individual Enterprise Security environments. Mitre Tactics and Techniques appear if using the annotation framework in Splunk ES."
```index=risk risk_object=\"{0}\" earliest=\"{1}\" latest="{2}\" | rex field=source \".*-\s(?<source>.*)\s+-\s+\w+\s+-\s+Rule\" | fillnull value=\"unknown\" threat_object | eval risk_message=coalesce(risk_message,source) | stats values(*) as * by _time source threat_object risk_message | rename annotations.mitre_attack.mitre_technique_id as mitre_technique_id annotations.mitre_attack.mitre_tactic as mitre_tactic annotations.mitre_attack.mitre_technique as mitre_technique | fields - annotations* risk_object_* date_* orig_* user_* src_user_* src_* dest_* dest_user_* info_* search_* splunk_* tag* risk_modifier* risk_rule* sourcetype timestamp index next_cron_time timeendpos timestartpos testmode linecount | sort + _time | `uitime(_time)` | dedup source threat_object```
A custom code block sorts the returned event data and produces a markdown formatted note into the note_content output field. This field is then available for use in downstream playbooks."


#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/risk_notable_import_data.png)

#### Required field


#### Reference

* [https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack](https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack)
* [http://docs.splunk.com/Documentation/ES/6.6.2/Admin/Configurecorrelationsearches#Use_security_framework_annotations_in_correlation_searches](http://docs.splunk.com/Documentation/ES/6.6.2/Admin/Configurecorrelationsearches#Use_security_framework_annotations_in_correlation_searches)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/risk_notable_import_data.yml) \| *version*: **1**