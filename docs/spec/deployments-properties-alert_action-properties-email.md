# Untitled object in Deployment Schema Schema

```txt
#/properties/alert_action/properties/email#/properties/alert_action/properties/email
```

By enabling it, an email is sent with the results

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                       |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [deployments.spec.json*](../../out/deployments.spec.json "open original schema") |

## email Type

`object` ([Details](deployments-properties-alert_action-properties-email.md))

## email Default Value

The default value is:

```json
{}
```

## email Examples

```yaml
message: Splunk Alert $name$ triggered %fields%
subject: Splunk Alert $name$
to: test@test.com

```

# email Properties

| Property              | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                   |
| :-------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [message](#message)   | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-alert_action-properties-email-properties-message.md "#/properties/alert_action/properties/email/properties/message#/properties/alert_action/properties/email/properties/message") |
| [subject](#subject)   | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-alert_action-properties-email-properties-subject.md "#/properties/alert_action/properties/email/properties/subject#/properties/alert_action/properties/email/properties/subject") |
| [to](#to)             | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-alert_action-properties-email-properties-to.md "#/properties/alert_action/properties/email/properties/to#/properties/alert_action/properties/email/properties/to")                |
| Additional Properties | Any      | Optional | can be null    |                                                                                                                                                                                                                              |

## message

message of email

`message`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action-properties-email-properties-message.md "#/properties/alert_action/properties/email/properties/message#/properties/alert_action/properties/email/properties/message")

### message Type

`string`

### message Examples

```yaml
Splunk Alert $name$ triggered %fields%

```

## subject

Subject of email

`subject`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action-properties-email-properties-subject.md "#/properties/alert_action/properties/email/properties/subject#/properties/alert_action/properties/email/properties/subject")

### subject Type

`string`

### subject Examples

```yaml
Splunk Alert $name$

```

## to

Recipient of email

`to`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-alert_action-properties-email-properties-to.md "#/properties/alert_action/properties/email/properties/to#/properties/alert_action/properties/email/properties/to")

### to Type

`string`

### to Examples

```yaml
test@test.com

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
