# Baseline Schema Schema

```txt
http://example.com/example.json
```

schema for baselines

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                  |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [baselines.spec.json](../../out/baselines.spec.json "open original schema") |

## Baseline Schema Type

`object` ([Baseline Schema](baselines.md))

# Baseline Schema Properties

| Property                              | Type      | Required | Nullable       | Defined by                                                                                                               |
| :------------------------------------ | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------- |
| [author](#author)                     | `string`  | Required | cannot be null | [Baseline Schema](baselines-properties-author.md "#/properties/author#/properties/author")                               |
| [date](#date)                         | `string`  | Required | cannot be null | [Baseline Schema](baselines-properties-date.md "#/properties/date#/properties/date")                                     |
| [description](#description)           | `string`  | Required | cannot be null | [Baseline Schema](baselines-properties-description.md "#/properties/description#/properties/description")                |
| [how_to_implement](#how_to_implement) | `string`  | Optional | cannot be null | [Baseline Schema](baselines-properties-how_to_implement.md "#/properties/how_to_implement#/properties/how_to_implement") |
| [id](#id)                             | `string`  | Required | cannot be null | [Baseline Schema](baselines-properties-id.md "#/properties/id#/properties/id")                                           |
| [name](#name)                         | `string`  | Required | cannot be null | [Baseline Schema](baselines-properties-name-of-baseline.md "#/properties/name#/properties/name")                         |
| [search](#search)                     | `string`  | Required | cannot be null | [Baseline Schema](baselines-properties-search.md "#/properties/search#/properties/search")                               |
| [tags](#tags)                         | `object`  | Required | cannot be null | [Baseline Schema](baselines-properties-tags.md "#/properties/tags#/properties/tags")                                     |
| [version](#version)                   | `integer` | Required | cannot be null | [Baseline Schema](baselines-properties-version.md "#/properties/version#/properties/version")                            |
| Additional Properties                 | Any       | Optional | can be null    |                                                                                                                          |

## author

Author of the baseline

`author`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Baseline Schema](baselines-properties-author.md "#/properties/author#/properties/author")

### author Type

`string`

### author Examples

```yaml
Bahvin Patel, Splunk

```

## date

date of creation or modification, format yyyy-mm-dd

`date`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Baseline Schema](baselines-properties-date.md "#/properties/date#/properties/date")

### date Type

`string`

### date Examples

```yaml
'2019-12-06'

```

## description

A detailed description of the baseline

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Baseline Schema](baselines-properties-description.md "#/properties/description#/properties/description")

### description Type

`string`

### description Examples

```yaml
>-
  This search looks for CloudTrail events where an AWS instance is started and
  creates a baseline of most recent time (latest) and the first time (earliest)
  we've seen this region in our dataset grouped by the value awsRegion for the
  last 30 days

```

## how_to_implement

information about how to implement. Only needed for non standard implementations.

`how_to_implement`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Baseline Schema](baselines-properties-how_to_implement.md "#/properties/how_to_implement#/properties/how_to_implement")

### how_to_implement Type

`string`

### how_to_implement Examples

```yaml
>-
  This search requires Sysmon Logs and a Sysmon configuration, which includes
  EventCode 10 for lsass.exe.

```

## id

UUID as unique identifier

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Baseline Schema](baselines-properties-id.md "#/properties/id#/properties/id")

### id Type

`string`

### id Examples

```yaml
fc0edc95-ff2b-48b0-9f6f-63da3789fd63

```

## name



`name`

*   is required

*   Type: `string` ([Name of baseline](baselines-properties-name-of-baseline.md))

*   cannot be null

*   defined in: [Baseline Schema](baselines-properties-name-of-baseline.md "#/properties/name#/properties/name")

### name Type

`string` ([Name of baseline](baselines-properties-name-of-baseline.md))

### name Examples

```yaml
Previously Seen AWS Regions

```

## search

The Splunk search for the baseline

`search`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Baseline Schema](baselines-properties-search.md "#/properties/search#/properties/search")

### search Type

`string`

### search Examples

```yaml
>-
  cloudtrail StartInstances | stats earliest(_time) as earliest latest(_time) as
  latest by awsRegion | outputlookup previously_seen_aws_regions.csv

```

## tags

An array of key value pairs for tagging

`tags`

*   is required

*   Type: `object` ([Details](baselines-properties-tags.md))

*   cannot be null

*   defined in: [Baseline Schema](baselines-properties-tags.md "#/properties/tags#/properties/tags")

### tags Type

`object` ([Details](baselines-properties-tags.md))

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
analytics_story: suspicious_aws_ec2_activities
custom_key: custom_value

```

## version

version of baseline, e.g. 1 or 2 ...

`version`

*   is required

*   Type: `integer`

*   cannot be null

*   defined in: [Baseline Schema](baselines-properties-version.md "#/properties/version#/properties/version")

### version Type

`integer`

### version Examples

```yaml
1

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
