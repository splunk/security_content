# Untitled object in Deployment Schema Schema

```txt
#/properties/alert_action/properties/index#/properties/alert_action/properties/index
```

By enabling it, the results are stored in another index

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                       |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [deployments.spec.json*](../../out/deployments.spec.json "open original schema") |

## index Type

`object` ([Details](deployments-properties-alert_action-properties-index.md))

## index Default Value

The default value is:

```json
{}
```

## index Examples

```yaml
name: asx

```

# index Properties

| Property              | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                          |
| :-------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [name](#name)         | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-alert_action-properties-index-properties-name.md "#/properties/alert_action/properties/index/properties/name#/properties/alert_action/properties/index/properties/name") |
| Additional Properties | Any      | Optional | can be null    |                                                                                                                                                                                                                     |

## name

Name of the index

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action-properties-index-properties-name.md "#/properties/alert_action/properties/index/properties/name#/properties/alert_action/properties/index/properties/name")

### name Type

`string`

### name Examples

```yaml
asx

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
