---
title: "Phishing Email Detection by Machine Learning Method - SSA"
excerpt: "Phishing"
categories:
  - Application
last_modified_at: 2020-08-25
toc: true
toc_label: ""
tags:
  - Phishing
  - Initial Access
  - Splunk Behavioral Analytics
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Malicious mails can conduct phishing that induces readers to open attachment, click links or trigger third party service. This detect uses Natural Language Processing (NLP) approach to analyze an email message&#39;s content (Sender, Subject and Body) and judge whether it is a phishing email. The detection adopts a deep learning (neural network) model that employs character level embeddings plus LSTM layers to perform classification. The model is pre-trained and then published as ONNX format. Current sample model is trained using the dataset published at https://github.com/splunk/attack_data/tree/master/datasets/T1566_Phishing_Email/splunk_train.json User are expected to re-train the model by combining with their own training data for better accuracy using the provided model file (SMLE notebook). DSP pipeline then processes the email message and passes it as an event to Apply ML Models function, which returns the probability of a phishing email. Current implementation assumes the email is fed to DSP in JSON format contains at least email&#39;s sender, subject and its message body, including reply content, if any.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2020-08-25
- **Author**: Xiao Lin, Splunk
- **ID**: 4b237388-dfa1-41a6-91d4-4de2d598376f


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

#### Search

```

| from read_ssa_enriched_events() 
| eval eventLine=concat(ucast(map_get(input_event, "From"), "string", " "), " ", ucast(map_get(input_event, "Subject"), "string", " "), " ", ucast(map_get(input_event, "Content"), "string", " "), "                                                                                                                                "), _time=map_get(input_event, "_time") 
| where eventLine IS NOT NULL 
| eval mapC={" ": 32, "!": 33, "\"": 34, "#": 35, "$": 36, "%": 37, "&": 38, "`": 39, "(": 40, ")": 41, "*": 42, "+": 43, ",": 44, "-": 45, ".": 46, "/": 47, "0": 48, "1": 49, "2": 50, "3": 51, "4": 52, "5": 53, "6": 54, "7": 55, "8": 56, "9": 57, ":": 58, ";": 59, "<": 60, "=": 61, ">": 62, "?": 63, "@": 64, "A": 65, "B": 66, "C": 67, "D": 68, "E": 69, "F": 70, "G": 71, "H": 72, "I": 73, "J": 74, "K": 75, "L": 76, "M": 77, "N": 78, "O": 79, "P": 80, "Q": 81, "R": 82, "S": 83, "T": 84, "U": 85, "V": 86, "W": 87, "X": 88, "Y": 89, "Z": 90, "[": 91, "\\": 92, "]": 93, "^": 94, "_": 95, "`": 96, "a": 97, "b": 98, "c": 99, "d": 100, "e": 101, "f": 102, "g": 103, "h": 104, "i": 105, "j": 106, "k": 107, "l": 108, "m": 109, "n": 110, "o": 111, "p": 112, "q": 113, "r": 114, "s": 115, "t": 116, "u": 117, "v": 118, "w": 119, "x": 120, "y": 121, "z": 122, "{": 123, "
|": 124, "}": 125, "~": 126}, ml_in = for_each(iterator(mvrange(1,129), "i"), cast(map_get(mapC, substr(eventLine, i, 1)), "float") ) 
| apply_model connection_id="YOUR_S3_ONNX_CONNECTOR_ID" name="phishing_email_v8" path="s3://smle-experiments/models/phishing_email" 
| eval probability = mvindex(ml_out, 0) 
| where probability > 0.5 
| eval start_time=_time, end_time=_time, entities="TBD", body="TBD" 
| select probability, body, entities, start_time, end_time 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `phishing_email_detection_by_machine_learning_method_-_ssa_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field


#### How To Implement
Events are fed to DSP contains at least email&#39;s sender, subject and its message body.

#### Known False Positives
Because of imbalance of anomaly data in training, the model will less likely report false positive. Instead, the model is more prone to false negative. Current best recall score is ~85%

#### Associated Analytic story


#### Kill Chain Phase
* Actions on Objectives




Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/phishing_email_detection_by_machine_learning_method_-_ssa.yml) \| *version*: **1**