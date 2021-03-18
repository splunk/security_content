# Response Schema Schema

```txt
https://raw.githubusercontent.com/splunk/security_content/develop/docs/spec/response_tasks.spec.json
```

schema for response task

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                            |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [response_tasks.spec.json](../../out/response_tasks.spec.json "open original schema") |

## Response Schema Type

`object` ([Response Schema](response_tasks.md))

## Response Schema Default Value

The default value is:

```json
{}
```

# Response Schema Properties

| Property                    | Type      | Required | Nullable       | Defined by                                                                                                     |
| :-------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------- |
| [author](#author)           | `string`  | Required | cannot be null | [Response Schema](response_tasks-properties-author.md "#/properties/author#/properties/author")                |
| [date](#date)               | `string`  | Required | cannot be null | [Response Schema](response_tasks-properties-date.md "#/properties/date#/properties/date")                      |
| [description](#description) | `string`  | Required | cannot be null | [Response Schema](response_tasks-properties-description.md "#/properties/description#/properties/description") |
| [id](#id)                   | `string`  | Required | cannot be null | [Response Schema](response_tasks-properties-id.md "#/properties/id#/properties/id")                            |
| [name](#name)               | `string`  | Required | cannot be null | [Response Schema](response_tasks-properties-name.md "#/properties/name#/properties/name")                      |
| [sla](#sla)                 | `integer` | Optional | cannot be null | [Response Schema](response_tasks-properties-sla.md "#/properties/sla#/properties/sla")                         |
| [sla_type](#sla_type)       | `string`  | Optional | cannot be null | [Response Schema](response_tasks-properties-sla_type.md "#/properties/sla_type#/properties/sla_type")          |
| [automation](#automation)   | `object`  | Optional | cannot be null | [Response Schema](response_tasks-properties-automation.md "#/properties/automation#/properties/automation")    |
| [tags](#tags)               | `object`  | Required | cannot be null | [Response Schema](response_tasks-properties-tags.md "#/properties/tags#/properties/tags")                      |
| [version](#version)         | `integer` | Required | cannot be null | [Response Schema](response_tasks-properties-version.md "#/properties/version#/properties/version")             |
| [references](#references)   | `array`   | Optional | cannot be null | [Response Schema](response_tasks-properties-references.md "#/properties/references#/properties/references")    |
| Additional Properties       | Any       | Optional | can be null    |                                                                                                                |

## author

Author of the response task

`author`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-author.md "#/properties/author#/properties/author")

### author Type

`string`

### author Examples

```yaml
ButterCup, Splunk

```

## date

date of creation or modification, format yyyy-mm-dd

`date`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-date.md "#/properties/date#/properties/date")

### date Type

`string`

### date Examples

```yaml
'2019-12-06'

```

## description

Description of response task

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-description.md "#/properties/description#/properties/description")

### description Type

`string`

### description Examples

```yaml
Response example.

```

## id

UUID as unique identifier

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-id.md "#/properties/id#/properties/id")

### id Type

`string`

### id Examples

```yaml
fb4c31b0-13e8-4155-8aa5-24de4b8d6717

```

## name

Name of response task

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-name.md "#/properties/name#/properties/name")

### name Type

`string`

### name Examples

```yaml
Response Example

```

## sla

Measured integer for Service Level Agreement for completion of the phase

`sla`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-sla.md "#/properties/sla#/properties/sla")

### sla Type

`integer`

### sla Examples

```yaml
5

```

```yaml
30

```

## sla_type

Duration for measured integer for Service Level Agreement for completion of the phase (e.g. minutes, or hours, etc)

`sla_type`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-sla_type.md "#/properties/sla_type#/properties/sla_type")

### sla_type Type

`string`

### sla_type Default Value

The default value is:

```json
"minutes"
```

### sla_type Examples

```yaml
minutes

```

```yaml
hours

```

```yaml
days

```

## automation

An array of key value pairs for defining actions and playbooks

`automation`

*   is optional

*   Type: `object` ([Details](response_tasks-properties-automation.md))

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-automation.md "#/properties/automation#/properties/automation")

### automation Type

`object` ([Details](response_tasks-properties-automation.md))

### automation Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

**unique items**: all items in this array must be unique. Duplicates are not allowed.

### automation Default Value

The default value is:

```json
{
  "is_note_required": false,
  "sla_type": "minutes",
  "sla": "",
  "role": "",
  "action": [],
  "playbooks": []
}
```

### automation Examples

```yaml
is_note_required: false
sla_type: minutes
sla: 30
action:
  - run_query
playbooks:
  - scm: local
    playbook: automate something
  - scm: local
    playbook: automate something else

```

## tags

An array of key value pairs for tagging

`tags`

*   is required

*   Type: `object` ([Details](response_tasks-properties-tags.md))

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-tags.md "#/properties/tags#/properties/tags")

### tags Type

`object` ([Details](response_tasks-properties-tags.md))

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
analytic_story: credential_dumping

```

## version

version of detection, e.g. 1 or 2 ...

`version`

*   is required

*   Type: `integer`

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-version.md "#/properties/version#/properties/version")

### version Type

`integer`

### version Examples

```yaml
1

```

## references

A list of references for this response, phase or task (e.g. web or printed citation)

`references`

*   is optional

*   Type: `string[]` ([Blue Team Handbook by Don Murdoch - Amazon](response_tasks-properties-references-blue-team-handbook-by-don-murdoch---amazon.md))

*   cannot be null

*   defined in: [Response Schema](response_tasks-properties-references.md "#/properties/references#/properties/references")

### references Type

`string[]` ([Blue Team Handbook by Don Murdoch - Amazon](response_tasks-properties-references-blue-team-handbook-by-don-murdoch---amazon.md))

### references Default Value

The default value is:

```json
[]
```

### references Examples

```yaml
- Blue Team Handbook by Don Murdoch - Alarm Triage Overview pages 146-148
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
