# Deployment Schema Schema

```txt
http://example.com/example.json
```

schema for deployment

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [deployments.spec.json](../../out/deployments.spec.json "open original schema") |

## Deployment Schema Type

`object` ([Deployment Schema](deployments.md))

## Deployment Schema Default Value

The default value is:

```json
{}
```

# Deployment Schema Properties

| Property                      | Type     | Required | Nullable       | Defined by                                                                                                       |
| :---------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------- |
| [alert_action](#alert_action) | `object` | Optional | cannot be null | [Deployment Schema](deployments-properties-alert_action.md "#/properties/alert_action#/properties/alert_action") |
| [date](#date)                 | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-date.md "#/properties/date#/properties/date")                         |
| [description](#description)   | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-description.md "#/properties/description#/properties/description")    |
| [id](#id)                     | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-id.md "#/properties/id#/properties/id")                               |
| [name](#name)                 | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-name.md "#/properties/name#/properties/name")                         |
| [scheduling](#scheduling)     | `object` | Required | cannot be null | [Deployment Schema](deployments-properties-scheduling.md "#/properties/scheduling#/properties/scheduling")       |
| [tags](#tags)                 | `object` | Required | cannot be null | [Deployment Schema](deployments-properties-tags.md "#/properties/tags#/properties/tags")                         |
| Additional Properties         | Any      | Optional | can be null    |                                                                                                                  |

## alert_action

Set alert action parameter for search

`alert_action`

*   is optional

*   Type: `object` ([Details](deployments-properties-alert_action.md))

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action.md "#/properties/alert_action#/properties/alert_action")

### alert_action Type

`object` ([Details](deployments-properties-alert_action.md))

### alert_action Default Value

The default value is:

```json
{}
```

### alert_action Examples

```yaml
email:
  message: Splunk Alert $name$ triggered %fields%
  subject: Splunk Alert $name$
  to: test@test.com
index:
  name: asx
notable:
  rule_description: '%description%'
  rule_title: '%name%'

```

## date

date of creation or modification, format yyyy-mm-dd

`date`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-date.md "#/properties/date#/properties/date")

### date Type

`string`

### date Examples

```yaml
'2019-12-06'

```

## description

description of the deployment configuration

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-description.md "#/properties/description#/properties/description")

### description Type

`string`

### description Examples

```yaml
>-
  This deployment configuration provides a standard scheduling policy over all
  rules.

```

## id

uuid as unique identifier

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-id.md "#/properties/id#/properties/id")

### id Type

`string`

### id Examples

```yaml
fb4c31b0-13e8-4155-8aa5-24de4b8d6717

```

## name

Name of deployment configuration

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-name.md "#/properties/name#/properties/name")

### name Type

`string`

### name Examples

```yaml
Deployment Configuration all Detections

```

## scheduling

allows to set scheduling parameter

`scheduling`

*   is required

*   Type: `object` ([Details](deployments-properties-scheduling.md))

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-scheduling.md "#/properties/scheduling#/properties/scheduling")

### scheduling Type

`object` ([Details](deployments-properties-scheduling.md))

### scheduling Default Value

The default value is:

```json
{}
```

### scheduling Examples

```yaml
cron_schedule: '*/10 * * * *'
earliest_time: '-10m'
latest_time: now
schedule_window: auto

```

## tags

An array of key value pairs for tagging

`tags`

*   is required

*   Type: `object` ([Details](deployments-properties-tags.md))

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-tags.md "#/properties/tags#/properties/tags")

### tags Type

`object` ([Details](deployments-properties-tags.md))

### tags Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

**unique items**: all items in this array must be unique. Duplicates are not allowed.

### tags Default Value

The default value is:

```json
{}
```

### tags Examples

```yaml
analytics_story: credential_dumping

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
