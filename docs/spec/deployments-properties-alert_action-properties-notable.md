# Untitled object in Deployment Schema Schema

```txt
#/properties/alert_action/properties/notable#/properties/alert_action/properties/notable
```

By enabling it, a notable is generated

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                       |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [deployments.spec.json*](../../out/deployments.spec.json "open original schema") |

## notable Type

`object` ([Details](deployments-properties-alert_action-properties-notable.md))

## notable Default Value

The default value is:

```json
{}
```

## notable Examples

```yaml
rule_description: '%description%'
rule_title: '%name%'

```

# notable Properties

| Property                              | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                    |
| :------------------------------------ | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [rule_description](#rule_description) | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-alert_action-properties-notable-properties-rule_description.md "#/properties/alert_action/properties/notable/properties/rule_description#/properties/alert_action/properties/notable/properties/rule_description") |
| [rule_title](#rule_title)             | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-alert_action-properties-notable-properties-rule_title.md "#/properties/alert_action/properties/notable/properties/rule_title#/properties/alert_action/properties/notable/properties/rule_title")                   |
| Additional Properties                 | Any      | Optional | can be null    |                                                                                                                                                                                                                                                               |

## rule_description

Rule description of the notable event

`rule_description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action-properties-notable-properties-rule_description.md "#/properties/alert_action/properties/notable/properties/rule_description#/properties/alert_action/properties/notable/properties/rule_description")

### rule_description Type

`string`

### rule_description Examples

```yaml
'%description%'

```

## rule_title

Rule title of the notable event

`rule_title`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action-properties-notable-properties-rule_title.md "#/properties/alert_action/properties/notable/properties/rule_title#/properties/alert_action/properties/notable/properties/rule_title")

### rule_title Type

`string`

### rule_title Examples

```yaml
'%name%'

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
