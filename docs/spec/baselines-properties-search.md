# Untitled string in Baseline Schema Schema

```txt
#/properties/search#/properties/search
```

The Splunk search for the baseline

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                   |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [baselines.spec.json*](../../out/baselines.spec.json "open original schema") |

## search Type

`string`

## search Examples

```yaml
>-
  cloudtrail StartInstances | stats earliest(_time) as earliest latest(_time) as
  latest by awsRegion | outputlookup previously_seen_aws_regions.csv

```
