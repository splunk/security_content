# Fidelity

The fidelity of a narrative describes the ratio of signal (valid/positive) to noise (invalid/false positive) anticipated based on field experience.

* High - This indicates a relatively high signal to noise ratio, and therefore a lower likelihood of false positives, and it should not require additional searches to validate it.

Example:

```

sourcetype=WinEventLog:* EventCode=4728
```



* Low - This indicates a relatively low signal to noise ratio, and therefore a higher likelihood of false positives.  Confidence in the output can be increased through other means (i.e. cross-correlation and/or subsequent searches).

Example:

```

url=* | eval url_length = len(url) | where url_length > 256
```
* Moderate - This indicates an unpredictable signal to noise ratio with a bias towards signal, and therefore a higher likelihood of false positives than high. Confidence in the output can be increased through other means (i.e. cross-correlation and/or subsequent searches).

Example:

```
http_user_agent = "*nullptr*"
```

