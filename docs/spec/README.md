# README

## Top-level Schemas

*   [Analytics Story Schema](./stories.md "schema analytics story") – `http://example.com/example.json`

*   [Baseline Schema](./baselines.md "schema for baselines") – `http://example.com/example.json`

*   [Deployment Schema](./deployments.md "schema for deployment") – `http://example.com/example.json`

*   [Detection Schema](./detections.md "schema for detections") – `http://example.com/example.json`

*   [Lookup Manifest](./lookups.md "A object that defines a lookup file and its properties") – `https://api.splunkresearch.com/schemas/lookups.json`

*   [Macro Manifest](./macros.md "An object that defines the parameters for a Splunk Macro") – `https://api.splunkresearch.com/schemas/macros.json`

*   [Response Schema](./response_tasks.md "schema for response task") – `https://raw.githubusercontent.com/splunk/security_content/develop/docs/spec/response_tasks.spec.json`

*   [Response Schema](./responses.md "schema for response") – `https://raw.githubusercontent.com/splunk/security_content/develop/docs/spec/response.spec.json`

*   [Response Schema](./responses_phase.md "schema for phase") – `http://example.com/example.json`

## Other Schemas

### Objects

*   [Untitled object in Baseline Schema](./baselines-properties-tags.md "An array of key value pairs for tagging") – `#/properties/tags#/properties/tags`

*   [Untitled object in Deployment Schema](./deployments-properties-alert_action.md "Set alert action parameter for search") – `#/properties/alert_action#/properties/alert_action`

*   [Untitled object in Deployment Schema](./deployments-properties-alert_action-properties-email.md "By enabling it, an email is sent with the results") – `#/properties/alert_action/properties/email#/properties/alert_action/properties/email`

*   [Untitled object in Deployment Schema](./deployments-properties-alert_action-properties-index.md "By enabling it, the results are stored in another index") – `#/properties/alert_action/properties/index#/properties/alert_action/properties/index`

*   [Untitled object in Deployment Schema](./deployments-properties-alert_action-properties-notable.md "By enabling it, a notable is generated") – `#/properties/alert_action/properties/notable#/properties/alert_action/properties/notable`

*   [Untitled object in Deployment Schema](./deployments-properties-scheduling.md "allows to set scheduling parameter") – `#/properties/scheduling#/properties/scheduling`

*   [Untitled object in Response Schema](./response_tasks-properties-automation.md "An array of key value pairs for defining actions and playbooks") – `#/properties/automation#/properties/automation`

### Arrays

*   [Untitled array in Baseline Schema](./baselines-properties-datamodel.md "datamodel used in the search") – `#/properties/datamodel#/properties/datamodel`

*   [Untitled array in Detection Schema](./detections-properties-references.md "A list of references for this detection") – `#/properties/references#/properties/references`

*   [Untitled array in Macro Manifest](./macros-properties-arguments.md "A list of the arguments being passed to this macro") – `https://api.splunkresearch.com/schemas/macros.json#/properties/arguments`

*   [Untitled array in Response Schema](./responses-properties-response_phase.md "Response divided into phases") – `#/properties/response_phases#/properties/response_phase`

*   [Untitled array in Response Schema](./responses_phase-properties-response_task.md "Response phase is divided into task(s) to be completed") – `#/properties/response_task#/properties/response_task`
