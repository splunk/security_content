# Untitled string in Baseline Schema Schema

```txt
#/properties/description#/properties/description
```

A detailed description of the baseline

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                   |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [baselines.spec.json*](../../out/baselines.spec.json "open original schema") |

## description Type

`string`

## description Examples

```yaml
>-
  This search looks for CloudTrail events where an AWS instance is started and
  creates a baseline of most recent time (latest) and the first time (earliest)
  we've seen this region in our dataset grouped by the value awsRegion for the
  last 30 days

```
