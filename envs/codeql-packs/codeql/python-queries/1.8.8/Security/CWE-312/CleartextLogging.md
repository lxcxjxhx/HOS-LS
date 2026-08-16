# Clear-text logging of sensitive information
If sensitive data is written to a log entry it could be exposed to an attacker who gains access to the logs.

Potential attackers can obtain sensitive user data when the log output is displayed. Additionally that data may expose system information such as full path names, system information, and sometimes usernames and passwords.


## Recommendation
Sensitive data should not be logged.


## Example
In the example the entire process environment is logged using \`print\`. Regular users of the production deployed application should not have access to this much information about the environment configuration.


```python
# BAD: Logging cleartext sensitive data
import os
print(f"[INFO] Environment: {os.environ}")
```
In the second example the data that is logged is not sensitive.


```python
not_sensitive_data = {'a': 1, 'b': 2}
# GOOD: it is fine to log data that is not sensitive
print(f"[INFO] Some object contains: {not_sensitive_data}")
```

## References
* OWASP: [Insertion of Sensitive Information into Log File](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/).
* Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
* Common Weakness Enumeration: [CWE-359](https://cwe.mitre.org/data/definitions/359.html).
* Common Weakness Enumeration: [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
