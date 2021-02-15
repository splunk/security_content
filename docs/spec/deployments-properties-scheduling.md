# Untitled object in Deployment Schema Schema

```txt
#/properties/scheduling#/properties/scheduling
```

allows to set scheduling parameter

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                       |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [deployments.spec.json*](../../out/deployments.spec.json "open original schema") |

## scheduling Type

`object` ([Details](deployments-properties-scheduling.md))

## scheduling Default Value

The default value is:

```json
{}
```

## scheduling Examples

```yaml
cron_schedule: '*/10 * * * *'
earliest_time: '-10m'
latest_time: now
schedule_window: auto

```

# scheduling Properties

| Property                            | Type     | Required | Nullable       | Defined by                                                                                                                                                                                  |
| :---------------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [cron_schedule](#cron_schedule)     | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-scheduling-properties-cron_schedule.md "#/properties/scheduling/properties/cron_schedule#/properties/scheduling/properties/cron_schedule")       |
| [earliest_time](#earliest_time)     | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-scheduling-properties-earliest_time.md "#/properties/scheduling/properties/earliest_time#/properties/scheduling/properties/earliest_time")       |
| [latest_time](#latest_time)         | `string` | Required | cannot be null | [Deployment Schema](deployments-properties-scheduling-properties-latest_time.md "#/properties/scheduling/properties/latest_time#/properties/scheduling/properties/latest_time")             |
| [schedule_window](#schedule_window) | `string` | Optional | cannot be null | [Deployment Schema](deployments-properties-scheduling-properties-schedule_window.md "#/properties/scheduling/properties/schedule_window#/properties/scheduling/properties/schedule_window") |
| Additional Properties               | Any      | Optional | can be null    |                                                                                                                                                                                             |

## cron_schedule

Cron schedule to schedule the Splunk searches.

`cron_schedule`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-scheduling-properties-cron_schedule.md "#/properties/scheduling/properties/cron_schedule#/properties/scheduling/properties/cron_schedule")

### cron_schedule Type

`string`

### cron_schedule Examples

```yaml
'*/10 * * * *'

```

## earliest_time

earliest time of search

`earliest_time`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-scheduling-properties-earliest_time.md "#/properties/scheduling/properties/earliest_time#/properties/scheduling/properties/earliest_time")

### earliest_time Type

`string`

### earliest_time Examples

```yaml
'-10m'

```

## latest_time

latest time of search

`latest_time`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-scheduling-properties-latest_time.md "#/properties/scheduling/properties/latest_time#/properties/scheduling/properties/latest_time")

### latest_time Type

`string`

### latest_time Examples

```yaml
now

```

## schedule_window

schedule window for search

`schedule_window`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Deployment Schema](deployments-properties-scheduling-properties-schedule_window.md "#/properties/scheduling/properties/schedule_window#/properties/scheduling/properties/schedule_window")

### schedule_window Type

`string`

### schedule_window Examples

```yaml
auto

```

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
