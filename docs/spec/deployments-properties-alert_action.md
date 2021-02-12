# Untitled object in Deployment Schema Schema

```txt
#/properties/alert_action#/properties/alert_action
```

Set alert action parameter for search

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                       |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [deployments.spec.json*](../../out/deployments.spec.json "open original schema") |

## alert_action Type

`object` ([Details](deployments-properties-alert_action.md))

## alert_action Default Value

The default value is:

```json
{}
```

## alert_action Examples

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

# alert_action Properties

| Property              | Type     | Required | Nullable       | Defined by                                                                                                                                                                |
| :-------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [email](#email)       | `object` | Optional | cannot be null | [Deployment Schema](deployments-properties-alert_action-properties-email.md "#/properties/alert_action/properties/email#/properties/alert_action/properties/email")       |
| [index](#index)       | `object` | Optional | cannot be null | [Deployment Schema](deployments-properties-alert_action-properties-index.md "#/properties/alert_action/properties/index#/properties/alert_action/properties/index")       |
| [notable](#notable)   | `object` | Optional | cannot be null | [Deployment Schema](deployments-properties-alert_action-properties-notable.md "#/properties/alert_action/properties/notable#/properties/alert_action/properties/notable") |
| Additional Properties | Any      | Optional | can be null    |                                                                                                                                                                           |

## email

By enabling it, an email is sent with the results

`email`

*   is optional

*   Type: `object` ([Details](deployments-properties-alert_action-properties-email.md))

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action-properties-email.md "#/properties/alert_action/properties/email#/properties/alert_action/properties/email")

### email Type

`object` ([Details](deployments-properties-alert_action-properties-email.md))

### email Default Value

The default value is:

```json
{}
```

### email Examples

```yaml
message: Splunk Alert $name$ triggered %fields%
subject: Splunk Alert $name$
to: test@test.com

```

## index

By enabling it, the results are stored in another index

`index`

*   is optional

*   Type: `object` ([Details](deployments-properties-alert_action-properties-index.md))

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action-properties-index.md "#/properties/alert_action/properties/index#/properties/alert_action/properties/index")

### index Type

`object` ([Details](deployments-properties-alert_action-properties-index.md))

### index Default Value

The default value is:

```json
{}
```

### index Examples

```yaml
name: asx

```

## notable

By enabling it, a notable is generated

`notable`

*   is optional

*   Type: `object` ([Details](deployments-properties-alert_action-properties-notable.md))

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action-properties-notable.md "#/properties/alert_action/properties/notable#/properties/alert_action/properties/notable")

### notable Type

`object` ([Details](deployments-properties-alert_action-properties-notable.md))

### notable Default Value

The default value is:

```json
{}
```

### notable Examples

```yaml
rule_description: '%description%'
rule_title: '%name%'

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
