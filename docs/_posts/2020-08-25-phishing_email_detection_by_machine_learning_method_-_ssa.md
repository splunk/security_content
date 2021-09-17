---
title: "Phishing Email Detection by Machine Learning Method - SSA"
excerpt: "Phishing"
categories:
  - Application
last_modified_at: 2020-08-25
toc: true
tags:
  - Anomaly
  - T1566
  - Phishing
  - Initial Access
  - Splunk Behavioral Analytics
  - Actions on Objectives
---

# Phishing Email Detection by Machine Learning Method - SSA

Malicious mails can conduct phishing that induces readers to open attachment, click links or trigger third party service. This detect uses Natural Language Processing (NLP) approach to analyze an email message&#39;s content (Sender, Subject and Body) and judge whether it is a phishing email. The detection adopts a deep learning (neural network) model that employs character level embeddings plus LSTM layers to perform classification. The model is pre-trained and then published as ONNX format. Current sample model is trained using the dataset published at https://github.com/splunk/attack_data/tree/master/datasets/T1566_Phishing_Email/splunk_train.json User are expected to re-train the model by combining with their own training data for better accuracy using the provided model file (SMLE notebook). DSP pipeline then processes the email message and passes it as an event to Apply ML Models function, which returns the probability of a phishing email. Current implementation assumes the email is fed to DSP in JSON format contains at least email&#39;s sender, subject and its message body, including reply content, if any.

- **Product**: Splunk Behavioral Analytics
- **Datamodel**:
- **ATT&CK**: [T1566](https://attack.mitre.org/techniques/T1566/)
- **Last Updated**: 2020-08-25
- **Author**: Xiao Lin, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1566 | Phishing | Initial Access |


#### Search

```

| from read_ssa_enriched_events() 
| eval eventLine=concat(ucast(map_get(input_event, &#34;From&#34;), &#34;string&#34;, &#34; &#34;), &#34; &#34;, ucast(map_get(input_event, &#34;Subject&#34;), &#34;string&#34;, &#34; &#34;), &#34; &#34;, ucast(map_get(input_event, &#34;Content&#34;), &#34;string&#34;, &#34; &#34;), &#34;                                                                                                                                &#34;), _time=map_get(input_event, &#34;_time&#34;) 
| where eventLine IS NOT NULL 
| eval mapC={&#34; &#34;: 32, &#34;!&#34;: 33, &#34;\&#34;&#34;: 34, &#34;#&#34;: 35, &#34;$&#34;: 36, &#34;%&#34;: 37, &#34;&amp;&#34;: 38, &#34;`&#34;: 39, &#34;(&#34;: 40, &#34;)&#34;: 41, &#34;*&#34;: 42, &#34;+&#34;: 43, &#34;,&#34;: 44, &#34;-&#34;: 45, &#34;.&#34;: 46, &#34;/&#34;: 47, &#34;0&#34;: 48, &#34;1&#34;: 49, &#34;2&#34;: 50, &#34;3&#34;: 51, &#34;4&#34;: 52, &#34;5&#34;: 53, &#34;6&#34;: 54, &#34;7&#34;: 55, &#34;8&#34;: 56, &#34;9&#34;: 57, &#34;:&#34;: 58, &#34;;&#34;: 59, &#34;&lt;&#34;: 60, &#34;=&#34;: 61, &#34;&gt;&#34;: 62, &#34;?&#34;: 63, &#34;@&#34;: 64, &#34;A&#34;: 65, &#34;B&#34;: 66, &#34;C&#34;: 67, &#34;D&#34;: 68, &#34;E&#34;: 69, &#34;F&#34;: 70, &#34;G&#34;: 71, &#34;H&#34;: 72, &#34;I&#34;: 73, &#34;J&#34;: 74, &#34;K&#34;: 75, &#34;L&#34;: 76, &#34;M&#34;: 77, &#34;N&#34;: 78, &#34;O&#34;: 79, &#34;P&#34;: 80, &#34;Q&#34;: 81, &#34;R&#34;: 82, &#34;S&#34;: 83, &#34;T&#34;: 84, &#34;U&#34;: 85, &#34;V&#34;: 86, &#34;W&#34;: 87, &#34;X&#34;: 88, &#34;Y&#34;: 89, &#34;Z&#34;: 90, &#34;[&#34;: 91, &#34;\\&#34;: 92, &#34;]&#34;: 93, &#34;^&#34;: 94, &#34;_&#34;: 95, &#34;`&#34;: 96, &#34;a&#34;: 97, &#34;b&#34;: 98, &#34;c&#34;: 99, &#34;d&#34;: 100, &#34;e&#34;: 101, &#34;f&#34;: 102, &#34;g&#34;: 103, &#34;h&#34;: 104, &#34;i&#34;: 105, &#34;j&#34;: 106, &#34;k&#34;: 107, &#34;l&#34;: 108, &#34;m&#34;: 109, &#34;n&#34;: 110, &#34;o&#34;: 111, &#34;p&#34;: 112, &#34;q&#34;: 113, &#34;r&#34;: 114, &#34;s&#34;: 115, &#34;t&#34;: 116, &#34;u&#34;: 117, &#34;v&#34;: 118, &#34;w&#34;: 119, &#34;x&#34;: 120, &#34;y&#34;: 121, &#34;z&#34;: 122, &#34;{&#34;: 123, &#34;
|&#34;: 124, &#34;}&#34;: 125, &#34;~&#34;: 126}, ml_in = for_each(iterator(mvrange(1,129), &#34;i&#34;), cast(map_get(mapC, substr(eventLine, i, 1)), &#34;float&#34;) ) 
| apply_model connection_id=&#34;YOUR_S3_ONNX_CONNECTOR_ID&#34; name=&#34;phishing_email_v8&#34; path=&#34;s3://smle-experiments/models/phishing_email&#34; 
| eval probability = mvindex(ml_out, 0) 
| where probability &gt; 0.5 
| eval start_time=_time, end_time=_time, entities=&#34;TBD&#34;, body=&#34;TBD&#34; 
| select probability, body, entities, start_time, end_time 
| into write_ssa_detected_events();
```

#### Associated Analytic Story


#### How To Implement
Events are fed to DSP contains at least email&#39;s sender, subject and its message body.

#### Required field


#### Kill Chain Phase

* Actions on Objectives


#### Known False Positives
Because of imbalance of anomaly data in training, the model will less likely report false positive. Instead, the model is more prone to false negative. Current best recall score is ~85%




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1

```
#############
# Automatically generated by doc_gen.py in https://github.com/splunk/security_content''
# On Date: 2021-09-17 11:18:22.142081 UTC''
# Author: Splunk Security Research''
# Contact: research@splunk.com''
#############
```