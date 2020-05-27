# Splunk Security Content 
![](static/logo.png) 

Welcome to the Splunk Security Content

This project gives you access to our repository of Analytic Stories that are security guides which provide background on TTPs, mapped to the MITRE framework, the Lockheed Martin Kill Chain, and CIS controls. They include Splunk searches, machine-learning algorithms, and Splunk Phantom playbooks (where available)—all designed to work together to detect, investigate, and respond to threats.

## View Our Content
You can review our Analytic Stories by category [here](stories_categories.md), or in our [Splunk App](https://github.com/splunk/security-content/releases). 

If you prefer working with the command line, check out our [API](https://docs.splunkresearch.com/?version=latest):

```
curl -s https://content.splunkresearch.com | jq
{
  "hello": "welcome to Splunks Research security content api"
}
```

## Getting Started

Once you've installed our [app](https://github.com/splunk/security-content/releases), we recommend using our Analytic Story Execution App [(ASX)](https://github.com/splunk/analytics_story_execution) to execute and schedule all of the detections a story automatically.   

## Test Out The Detections
The [attack_range](https://http://github.com/splunk/attack_range) project allows you to spin up an enviroment and launch attacks against it to test the detections. 

## Questions?
If you get stuck or need help with any of our tools, see our [support options](https://github.com/splunk/security-content#support). 

## Contribute Content
If you want to help the rest of the security community by sharing your own detections, see our [contributor guide](https://github.com/splunk/security-content/blob/develop/docs/CONTRIBUTING.md). Digital defenders unite!


## Content Parts
* [stories/](stories/): All Analytic Stories
* [detections/](detections/): Splunk Enterprise, Splunk UBA, and Splunk Phantom detections that power Analytic Stories
* [response_tasks/](response_tasks/): Splunk Enterprise and Splunk Phantom investigative searches and playbooks employed by Analytic Stories
* [responses/](responses/): Automated Splunk Enterprise and Splunk Phantom responses triggered by Analytic Stories
* [baselines/](baselines/): Splunk Phantom and Splunk Enterprise baseline searches needed to support detection searches in Analytic Stories

#### Content Spec Files
* [stories](docs/spec/stories.spec.md) 
* [detections](docs/spec/detections.spec.md)
* [deployments](docs/spec/deployments.spec.md)
* [responses](docs/spec/responses.spec.md)
* [response_tasks](docs/spec/response_tasks.spec.md)
* [baselines](docs/spec/baselines.spec.md)
* [lookups](docs/spec/lookups.spec.md)
* [macros](docs/spec/macros.spec.md)



