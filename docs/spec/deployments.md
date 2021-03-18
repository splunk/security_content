# Deployment Schema


*schema for deployment*


## Properties


- **`alert_action`** *(object)*: Set alert action parameter for search. Can contain additional properties. Default: `{}`.

  - **`email`** *(object)*: By enabling it, an email is sent with the results. Can contain additional properties. Default: `{}`.

    - **`message`** *(string)*: message of email. Default: ``.

    - **`subject`** *(string)*: Subject of email. Default: ``.

    - **`to`** *(string)*: Recipient of email. Default: ``.

  - **`index`** *(object)*: By enabling it, the results are stored in another index. Can contain additional properties. Default: `{}`.

    - **`name`** *(string)*: Name of the index. Default: ``.

  - **`notable`** *(object)*: By enabling it, a notable is generated. Can contain additional properties. Default: `{}`.

    - **`rule_description`** *(string)*: Rule description of the notable event. Default: ``.

    - **`rule_title`** *(string)*: Rule title of the notable event. Default: ``.

- **`date`** *(string)*: date of creation or modification, format yyyy-mm-dd. Default: ``.

- **`description`** *(string)*: description of the deployment configuration. Default: ``.

- **`id`** *(string)*: uuid as unique identifier. Default: ``.

- **`name`** *(string)*: Name of deployment configuration. Default: ``.

- **`scheduling`** *(object)*: allows to set scheduling parameter. Can contain additional properties. Default: `{}`.

  - **`cron_schedule`** *(string)*: Cron schedule to schedule the Splunk searches. Default: ``.

  - **`earliest_time`** *(string)*: earliest time of search. Default: ``.

  - **`latest_time`** *(string)*: latest time of search. Default: ``.

  - **`schedule_window`** *(string)*: schedule window for search. Default: ``.

- **`tags`** *(object)*: An array of key value pairs for tagging. Can contain additional properties. Default: `{}`.
