# Splunk Security Content
![](static/logo.png)

Welcome to the Splunk Security Content

This project gives you access to our repository of Analytic Stories that are security guides which provide background on TTPs, mapped to the MITRE framework, the Lockheed Martin Kill Chain, and CIS controls. They include Splunk searches, machine-learning algorithms, and Splunk Phantom playbooks (where available)—all designed to work together to detect, investigate, and respond to threats.

## View Our Content

* [Analytic Stories](docs/stories.md)
* [Detections](docs/detections.md)

If you prefer working with the command line, check out our [API](https://docs.splunkresearch.com/?version=latest):

```
curl -s https://content.splunkresearch.com | jq
{
  "hello": "welcome to Splunks Research security content api"
}
```

## Test Out The Detections
The [attack_range](https://github.com/splunk/attack_range) project allows you to spin up an enviroment and launch attacks against it to test the detections.

## Questions?
If you get stuck or need help with any of our tools, see our [support options](https://github.com/splunk/security_content#support).

## Contribute Content
If you want to help the rest of the security community by sharing your own detections, see our [contributor guide](https://github.com/splunk/security_content/blob/develop/docs/CONTRIBUTING.md). Digital defenders unite!


## Content Parts
* [stories/](https://github.com/splunk/security_content/tree/develop/stories): All Analytic Stories
* [detections/](https://github.com/splunk/security_content/tree/develop/detections): Splunk Enterprise, Splunk UBA, and Splunk Phantom detections that power Analytic Stories
* [response_tasks/](https://github.com/splunk/security_content/tree/develop/response_tasks): Splunk Enterprise and Splunk Phantom investigative searches and playbooks employed by Analytic Stories
* [responses/](https://github.com/splunk/security_content/tree/develop/responses): Automated Splunk Enterprise and Splunk Phantom responses triggered by Analytic Stories
* [baselines/](https://github.com/splunk/security_content/tree/develop/baselines): Splunk Phantom and Splunk Enterprise baseline searches needed to support detection searches in Analytic Stories

#### Content Spec Files
* [stories](https://github.com/splunk/security_content/blob/develop/docs/spec/stories.spec.md)
* [detections](https://github.com/splunk/security_content/blob/develop/docs/spec/detections.spec.md)
* [deployments](https://github.com/splunk/security_content/blob/develop/docs/spec/deployments.spec.md)
* [responses](https://github.com/splunk/security_content/blob/develop/docs/spec/responses.spec.md)
* [response_tasks](https://github.com/splunk/security_content/blob/develop/docs/spec/response_tasks.spec.md)
* [baselines](https://github.com/splunk/security_content/blob/develop/docs/spec/baselines.spec.md)
* [lookups](https://github.com/splunk/security_content/blob/develop/docs/spec/lookups.spec.md)
* [macros](https://github.com/splunk/security_content/blob/develop/docs/spec/macros.spec.md)
