# Untitled object in Baseline Schema Schema

```txt
#/properties/tags#/properties/tags
```

An array of key value pairs for tagging

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                   |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [baselines.spec.json*](../../out/baselines.spec.json "open original schema") |

## tags Type

`object` ([Details](baselines-properties-tags.md))

## tags Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

**unique items**: all items in this array must be unique. Duplicates are not allowed.

## tags Default Value

The default value is:

```json
{}
```

## tags Examples

```yaml
analytics_story: suspicious_aws_ec2_activities
custom_key: custom_value

```

# tags Properties

| Property              | Type | Required | Nullable    | Defined by |
| :-------------------- | :--- | :------- | :---------- | :--------- |
| Additional Properties | Any  | Optional | can be null |            |

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
